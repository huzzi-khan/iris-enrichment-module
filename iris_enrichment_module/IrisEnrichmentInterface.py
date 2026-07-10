import traceback
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes
import iris_enrichment_module.IrisEnrichmentConfig as interface_conf


class IrisEnrichmentModInterface(IrisModuleInterface):
    """
    Main IRIS module class for automated IOC enrichment.
    IRIS loads this class and calls it when IOC events fire.
    """

    # ── Module declaration ────────────────────────────────
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        """
        Called by IRIS when loading the module.
        Registers which hooks this module wants to receive
        based on admin configuration.
        """
        module_conf = self.module_dict_conf

        # Hook 1 — auto trigger on IOC create
        if module_conf.get("auto_trigger_on_create"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_create"
            )
            if status.is_failure():
                self.log.error(
                    f"Failed to register on_postload_ioc_create: "
                    f"{status.get_message()}"
                )
            else:
                self.log.info("Registered hook: on_postload_ioc_create")

        # Hook 2 — auto trigger on IOC update
        if module_conf.get("auto_trigger_on_update"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_update"
            )
            if status.is_failure():
                self.log.error(
                    f"Failed to register on_postload_ioc_update: "
                    f"{status.get_message()}"
                )
            else:
                self.log.info("Registered hook: on_postload_ioc_update")

        # Hook 3 — manual trigger
        if module_conf.get("manual_trigger_enabled"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_manual_trigger_ioc"
            )
            if status.is_failure():
                self.log.error(
                    f"Failed to register on_manual_trigger_ioc: "
                    f"{status.get_message()}"
                )
            else:
                self.log.info("Registered hook: on_manual_trigger_ioc")

        return InterfaceStatus.I2Success()

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        """
        Called by IRIS every time a registered event fires.
        Routes the event to the correct handler.
        """
        self.log.info(f"Hook received: {hook_name}")

        if hook_name in [
            "on_postload_ioc_create",
            "on_postload_ioc_update",
            "on_manual_trigger_ioc"
        ]:
            return self._handle_ioc(data)

        self.log.warning(f"Unhandled hook: {hook_name}")
        return InterfaceStatus.I2Success(
            data=data,
            logs=list(self.message_queue)
        )

    def _handle_ioc(self, data):
        """
        Main enrichment handler.
        Receives IOC data from IRIS, runs enrichment,
        writes verdict back to the IOC custom attributes.
        """
        try:
            # ── Step 1: Extract IOC from data ─────────────
            ioc = data.get("ioc")
            if not ioc:
                self.log.error("No IOC found in hook data")
                return InterfaceStatus.I2Error(
                    data=data,
                    logs=list(self.message_queue)
                )

            ioc_value = ioc.ioc_value
            ioc_type = ioc.ioc_type.type_name if ioc.ioc_type else "unknown"
            ioc_id = ioc.ioc_id

            self.log.info(
                f"Enriching IOC #{ioc_id}: "
                f"{ioc_value} (type: {ioc_type})"
            )

            # ── Step 2: Get config values ─────────────────
            mod_conf = self.module_dict_conf
            mal_threshold = float(
                mod_conf.get("malicious_threshold", 80)
            )
            sus_threshold = float(
                mod_conf.get("suspicious_threshold", 60)
            )
            cache_enabled = mod_conf.get("cache_enabled", True)
            cache_ttl = float(mod_conf.get("cache_ttl_hours", 24)) * 3600

            # ── Step 3: Check cache ───────────────────────
            from iris_enrichment_module.cache import cache
            if cache_enabled:
                cached = cache.get(ioc_value)
                if cached:
                    self.log.info(
                        f"Cache hit for {ioc_value} — "
                        f"skipping feed queries"
                    )
                    self._write_to_ioc(ioc, cached, data)
                    return InterfaceStatus.I2Success(
                        data=data,
                        logs=list(self.message_queue)
                    )

            # ── Step 4: Run enrichment ────────────────────
            feed_results = self._run_feeds(
                ioc_value, ioc_type, mod_conf
            )

            # ── Step 5: Compute verdict ───────────────────
            from iris_enrichment_module.verdict import make_verdict
            verdict = make_verdict(feed_results, ioc_type, ioc_value)

            self.log.info(
                f"Verdict for {ioc_value}: "
                f"{verdict['verdict']} (score: {verdict['score']})"
            )

            # ── Step 6: Store in cache ────────────────────
            if cache_enabled:
                cache.set(ioc_value, verdict)

            # ── Step 7: Write to IRIS IOC ─────────────────
            self._write_to_ioc(ioc, verdict, data)

            return InterfaceStatus.I2Success(
                data=data,
                logs=list(self.message_queue)
            )

        except Exception as e:
            self.log.error(
                f"Unhandled error in _handle_ioc: {e}\n"
                f"{traceback.format_exc()}"
            )
            return InterfaceStatus.I2Error(
                data=data,
                logs=list(self.message_queue)
            )

    def _run_feeds(self, ioc_value, ioc_type, mod_conf):
        """
        Routes the IOC to the correct feed clients
        based on IOC type and enabled feeds in config.
        Returns list of raw feed result dicts.
        """
        results = []

        # Define IOC type groups
        ip_types = [
            "ip-any", "ip-dst", "ip-src",
            "ip-dst|port", "ip-src|port"
        ]
        domain_types = ["domain", "hostname", "domain|ip"]
        hash_types = ["md5", "sha1", "sha256", "sha512"]
        url_types = ["url"]
        email_types = ["email", "email-src", "email-dst", "email-reply-to"]
        cve_types = ["vulnerability", "cve"]
        asn_types = ["asn"]

        # ── IP enrichment ─────────────────────────────────
        if ioc_type in ip_types:
            if mod_conf.get("abuseipdb_enabled"):
                from iris_enrichment_module.feeds.abuseipdb import lookup_ip
                self.log.info(f"Querying AbuseIPDB for {ioc_value}")
                results.append(lookup_ip(ioc_value))

            if mod_conf.get("virustotal_enabled"):
                from iris_enrichment_module.feeds.virustotal import lookup_ip as vt_ip
                self.log.info(f"Querying VirusTotal for {ioc_value}")
                results.append(vt_ip(ioc_value))

        # ── Domain enrichment ─────────────────────────────
        elif ioc_type in domain_types:
            if mod_conf.get("virustotal_enabled"):
                from iris_enrichment_module.feeds.virustotal import lookup_domain
                self.log.info(f"Querying VirusTotal domain for {ioc_value}")
                results.append(lookup_domain(ioc_value))

            if mod_conf.get("urlhaus_enabled"):
                from iris_enrichment_module.feeds.urlhaus import lookup_host
                self.log.info(f"Querying URLhaus host for {ioc_value}")
                results.append(lookup_host(ioc_value))

        # ── Hash enrichment ───────────────────────────────
        elif ioc_type in hash_types:
            if mod_conf.get("virustotal_enabled"):
                from iris_enrichment_module.feeds.virustotal import lookup_hash
                self.log.info(f"Querying VirusTotal hash for {ioc_value}")
                results.append(lookup_hash(ioc_value))

            if mod_conf.get("malwarebazaar_enabled"):
                from iris_enrichment_module.feeds.malwarebazaar import lookup_hash as mb
                self.log.info(f"Querying MalwareBazaar for {ioc_value}")
                results.append(mb(ioc_value))

        # ── URL enrichment ────────────────────────────────
        elif ioc_type in url_types:
            if mod_conf.get("virustotal_enabled"):
                from iris_enrichment_module.feeds.virustotal import lookup_url as vt_url
                self.log.info(f"Querying VirusTotal URL for {ioc_value}")
                results.append(vt_url(ioc_value))

            if mod_conf.get("urlhaus_enabled"):
                from iris_enrichment_module.feeds.urlhaus import lookup_url
                self.log.info(f"Querying URLhaus URL for {ioc_value}")
                results.append(lookup_url(ioc_value))

        # ── Email enrichment ──────────────────────────────
        elif ioc_type in email_types:
            if mod_conf.get("emailrep_enabled"):
                from iris_enrichment_module.feeds.emailrep import lookup_email
                self.log.info(f"Querying EmailRep for {ioc_value}")
                results.append(lookup_email(ioc_value))

        # ── CVE enrichment ────────────────────────────────
        elif ioc_type in cve_types:
            if mod_conf.get("nvd_enabled"):
                from iris_enrichment_module.feeds.nvd import lookup_cve
                self.log.info(f"Querying NVD for {ioc_value}")
                results.append(lookup_cve(ioc_value))

        # ── ASN enrichment ────────────────────────────────
        elif ioc_type in asn_types:
            from iris_enrichment_module.feeds.ripe import lookup_asn
            self.log.info(f"Querying RIPE for {ioc_value}")
            results.append(lookup_asn(ioc_value))

        else:
            self.log.warning(
                f"No feed configured for IOC type: {ioc_type}"
            )
            results.append({
                "error": "unsupported_type",
                "source": "enrichment_module"
            })

        return results

    def _write_to_ioc(self, ioc, verdict, data):
        """
        Writes the enrichment verdict to the IOC's
        custom attributes in IRIS.
        Uses IRIS internal database session — no HTTP calls.
        """
        try:
            # Build the HTML report for the custom attribute
            html_report = self._build_html_report(verdict)

            # Add as a custom attribute to the IOC
            # This follows the same pattern as IrisVT
            status = self.add_ioc_attribute(
                ioc_id=ioc.ioc_id,
                attribute_name="Enrichment",
                attribute_value=html_report,
                attribute_display_name="Threat Intelligence Enrichment"
            )

            if status and status.is_failure():
                self.log.error(
                    f"Failed to write attribute to IOC "
                    f"#{ioc.ioc_id}: {status.get_message()}"
                )
            else:
                self.log.info(
                    f"Enrichment written to IOC #{ioc.ioc_id}"
                )

            # Also add verdict as a tag on the IOC
            verdict_label = verdict.get("verdict", "UNKNOWN")
            self.add_ioc_tag(
                ioc_id=ioc.ioc_id,
                tag=f"enrichment:{verdict_label.lower()}"
            )

        except Exception as e:
            self.log.error(
                f"Error writing to IOC: {e}\n"
                f"{traceback.format_exc()}"
            )

    def _build_html_report(self, verdict):
        """
        Builds an HTML string for display in the
        IRIS custom attribute tab on the IOC.
        Analysts see this as a formatted card.
        """
        verdict_label = verdict.get("verdict", "UNKNOWN")
        score = verdict.get("score", 0)
        sources = verdict.get("feed_sources", "unknown")
        country = verdict.get("country", "unknown")
        isp = verdict.get("isp", "unknown")
        is_tor = verdict.get("is_tor", False)
        tags = verdict.get("tags", "")
        malware_family = verdict.get("malware_family", "unknown")
        malicious_count = verdict.get("malicious_count", "0/0")
        enrichment_date = verdict.get("enrichment_date", "unknown")
        raw_detail = verdict.get("raw_detail", "").replace("\n", "<br>")

        # Colour the verdict badge
        if verdict_label == "MALICIOUS":
            badge_colour = "#dc3545"
        elif verdict_label == "SUSPICIOUS":
            badge_colour = "#fd7e14"
        elif verdict_label == "CLEAN":
            badge_colour = "#28a745"
        else:
            badge_colour = "#6c757d"

        html = f"""
<div class="row">
    <div class="col-12">
        <h3>Enrichment Summary</h3>
        <dl class="row">
            <dt class="col-sm-3">Verdict</dt>
            <dd class="col-sm-9">
                <span style="background:{badge_colour};color:white;
                padding:3px 10px;border-radius:4px;font-weight:bold;">
                    {verdict_label}
                </span>
            </dd>

            <dt class="col-sm-3">Confidence Score</dt>
            <dd class="col-sm-9">{score} / 100</dd>

            <dt class="col-sm-3">Malicious Sources</dt>
            <dd class="col-sm-9">{malicious_count}</dd>

            <dt class="col-sm-3">Feed Sources</dt>
            <dd class="col-sm-9">{sources}</dd>

            <dt class="col-sm-3">Country</dt>
            <dd class="col-sm-9">{country}</dd>

            <dt class="col-sm-3">ISP / AS Owner</dt>
            <dd class="col-sm-9">{isp}</dd>

            <dt class="col-sm-3">Tor Exit Node</dt>
            <dd class="col-sm-9">{is_tor}</dd>

            <dt class="col-sm-3">Malware Family</dt>
            <dd class="col-sm-9">{malware_family}</dd>

            <dt class="col-sm-3">Tags</dt>
            <dd class="col-sm-9">{tags}</dd>

            <dt class="col-sm-3">Enriched At</dt>
            <dd class="col-sm-9">{enrichment_date}</dd>
        </dl>
    </div>
</div>

<div class="row">
    <div class="col-12">
        <div class="accordion">
            <h3>Raw Detail</h3>
            <div class="card">
                <div class="card-header collapsed" id="drop_raw_enrich"
                     data-toggle="collapse"
                     data-target="#drop_raw_enrich_body"
                     aria-expanded="false" role="button">
                    <div class="span-title">Full enrichment detail</div>
                    <div class="span-mode"></div>
                </div>
                <div id="drop_raw_enrich_body" class="collapse"
                     aria-labelledby="drop_raw_enrich">
                    <div class="card-body">
                        <pre>{raw_detail}</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""
        return html