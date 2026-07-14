import traceback
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes
import iris_enrichment_module.IrisEnrichmentConfig as interface_conf


class IrisEnrichmentInterface(IrisModuleInterface):

    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        module_conf = self.module_dict_conf

        if module_conf.get("auto_trigger_on_create"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_create"
            )
            if status.is_failure():
                self.log.error(f"Failed to register on_postload_ioc_create: {status.get_message()}")
            else:
                self.log.info("Registered hook: on_postload_ioc_create")

        if module_conf.get("auto_trigger_on_update"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_update"
            )
            if status.is_failure():
                self.log.error(f"Failed to register on_postload_ioc_update: {status.get_message()}")
            else:
                self.log.info("Registered hook: on_postload_ioc_update")

        if module_conf.get("manual_trigger_enabled"):
            status = self.register_to_hook(
                module_id,
                iris_hook_name="on_manual_trigger_ioc"
            )
            if status.is_failure():
                self.log.error(f"Failed to register on_manual_trigger_ioc: {status.get_message()}")
            else:
                self.log.info("Registered hook: on_manual_trigger_ioc")

        return InterfaceStatus.I2Success()

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
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
        try:
            # ── Step 1: Extract IOC ───────────────────────
            if isinstance(data, list):
                if not data:
                    self.log.error("Empty data list received")
                    return InterfaceStatus.I2Error(
                        data=data, logs=list(self.message_queue)
                    )
                ioc = data[0]
            elif isinstance(data, dict):
                ioc = data.get("ioc")
            else:
                ioc = data

            if not ioc:
                self.log.error("No IOC found in hook data")
                return InterfaceStatus.I2Error(
                    data=data, logs=list(self.message_queue)
                )

            try:
                ioc_value = ioc.ioc_value
                ioc_type = ioc.ioc_type.type_name if ioc.ioc_type else "unknown"
                ioc_id = ioc.ioc_id
            except AttributeError as e:
                self.log.error(f"Could not extract IOC fields: {e}")
                return InterfaceStatus.I2Error(
                    data=data, logs=list(self.message_queue)
                )

            self.log.info(f"Enriching IOC #{ioc_id}: {ioc_value} (type: {ioc_type})")

            # ── Step 2: Get config ────────────────────────
            mod_conf = self.module_dict_conf
            cache_enabled = bool(mod_conf.get("cache_enabled", True))
            cache_ttl = float(mod_conf.get("cache_ttl_hours", 24)) * 3600

            # ── Step 3: Check cache ───────────────────────
            from iris_enrichment_module.cache import EnrichmentCache
            _cache = EnrichmentCache(ttl_seconds=cache_ttl, enabled=cache_enabled)

            if cache_enabled:
                cached = _cache.get(ioc_value)
                if cached:
                    self.log.info(f"Cache hit for {ioc_value}")
                    self._write_to_ioc(ioc, cached)
                    return InterfaceStatus.I2Success(
                        data=data, logs=list(self.message_queue)
                    )

            # ── Step 4: Run feeds ─────────────────────────
            feed_results = self._run_feeds(ioc_value, ioc_type, mod_conf)

            # ── Step 5: Compute verdict ───────────────────
            from iris_enrichment_module.verdict import make_verdict
            verdict = make_verdict(feed_results, ioc_type, ioc_value)

            self.log.info(
                f"Verdict for {ioc_value}: "
                f"{verdict['verdict']} (score: {verdict['score']})"
            )

            # ── Step 6: Cache result ──────────────────────
            if cache_enabled:
                _cache.set(ioc_value, verdict)

            # ── Step 7: Write to IRIS ─────────────────────
            self._write_to_ioc(ioc, verdict)

            return InterfaceStatus.I2Success(
                data=data, logs=list(self.message_queue)
            )

        except Exception as e:
            self.log.error(
                f"Unhandled error in _handle_ioc: {e}\n"
                f"{traceback.format_exc()}"
            )
            return InterfaceStatus.I2Error(
                data=data, logs=list(self.message_queue)
            )

    def _run_feeds(self, ioc_value, ioc_type, mod_conf):
        results = []

        abuseipdb_key = mod_conf.get("abuseipdb_api_key")
        vt_key = mod_conf.get("virustotal_api_key")
        urlhaus_key = mod_conf.get("urlhaus_api_key")
        mb_key = mod_conf.get("malwarebazaar_api_key")
        emailrep_key = mod_conf.get("emailrep_api_key")
        nvd_key = mod_conf.get("nvd_api_key")

        ip_types = ["ip-any", "ip-dst", "ip-src", "ip-dst|port", "ip-src|port"]
        domain_types = ["domain", "hostname", "domain|ip"]
        hash_types = ["md5", "sha1", "sha256", "sha512"]
        url_types = ["url"]
        email_types = ["email", "email-src", "email-dst", "email-reply-to"]
        cve_types = ["vulnerability", "cve"]
        asn_types = ["asn"]

        if ioc_type in ip_types:
            if mod_conf.get("abuseipdb_enabled") and abuseipdb_key:
                from iris_enrichment_module.feeds.abuseipdb import lookup_ip
                self.log.info(f"Querying AbuseIPDB for {ioc_value}")
                results.append(lookup_ip(ioc_value, abuseipdb_key))

            if mod_conf.get("virustotal_enabled") and vt_key:
                from iris_enrichment_module.feeds.virustotal import lookup_ip as vt_ip
                self.log.info(f"Querying VirusTotal for {ioc_value}")
                results.append(vt_ip(ioc_value, vt_key))

        elif ioc_type in domain_types:
            if mod_conf.get("virustotal_enabled") and vt_key:
                from iris_enrichment_module.feeds.virustotal import lookup_domain
                self.log.info(f"Querying VirusTotal domain for {ioc_value}")
                results.append(lookup_domain(ioc_value, vt_key))

            if mod_conf.get("urlhaus_enabled"):
                from iris_enrichment_module.feeds.urlhaus import lookup_host
                self.log.info(f"Querying URLhaus host for {ioc_value}")
                results.append(lookup_host(ioc_value, urlhaus_key))

        elif ioc_type in hash_types:
            if mod_conf.get("virustotal_enabled") and vt_key:
                from iris_enrichment_module.feeds.virustotal import lookup_hash
                self.log.info(f"Querying VirusTotal hash for {ioc_value}")
                results.append(lookup_hash(ioc_value, vt_key))

            if mod_conf.get("malwarebazaar_enabled") and mb_key:
                from iris_enrichment_module.feeds.malwarebazaar import lookup_hash as mb
                self.log.info(f"Querying MalwareBazaar for {ioc_value}")
                results.append(mb(ioc_value, mb_key))

        elif ioc_type in url_types:
            if mod_conf.get("virustotal_enabled") and vt_key:
                from iris_enrichment_module.feeds.virustotal import lookup_url as vt_url
                self.log.info(f"Querying VirusTotal URL for {ioc_value}")
                results.append(vt_url(ioc_value, vt_key))

            if mod_conf.get("urlhaus_enabled"):
                from iris_enrichment_module.feeds.urlhaus import lookup_url
                self.log.info(f"Querying URLhaus URL for {ioc_value}")
                results.append(lookup_url(ioc_value, urlhaus_key))

        elif ioc_type in email_types:
            if mod_conf.get("emailrep_enabled") and emailrep_key:
                from iris_enrichment_module.feeds.emailrep import lookup_email
                self.log.info(f"Querying EmailRep for {ioc_value}")
                results.append(lookup_email(ioc_value, emailrep_key))

        elif ioc_type in cve_types:
            if mod_conf.get("nvd_enabled"):
                from iris_enrichment_module.feeds.nvd import lookup_cve
                self.log.info(f"Querying NVD for {ioc_value}")
                results.append(lookup_cve(ioc_value, nvd_key))

        elif ioc_type in asn_types:
            from iris_enrichment_module.feeds.ripe import lookup_asn
            self.log.info(f"Querying RIPE for {ioc_value}")
            results.append(lookup_asn(ioc_value))

        else:
            self.log.warning(f"No feed configured for IOC type: {ioc_type}")
            results.append({
                "error": "unsupported_type",
                "source": "enrichment_module"
            })

        return results

    def _write_to_ioc(self, ioc, verdict):
        """
        Writes enrichment verdict to IRIS IOC using the same
        pattern as IrisVT — add_tab_attribute_field for the
        HTML report and direct ioc_tags modification for tags.
        """
        try:
            from app.datamgmt.manage.manage_attribute_db import (
                add_tab_attribute_field
            )

            html_report = self._build_html_report(verdict)

            # Write HTML report as a custom attribute tab
            # exactly the same way IrisVT does it
            add_tab_attribute_field(
                ioc,
                tab_name="Enrichment",
                field_name="Threat Intelligence",
                field_type="html",
                field_value=html_report
            )

            self.log.info(f"Enrichment attribute written to IOC #{ioc.ioc_id}")

            # Write verdict as a tag directly on the IOC object
            verdict_label = verdict.get("verdict", "UNKNOWN").lower()
            tag = f"enrichment:{verdict_label}"

            if ioc.ioc_tags is None:
                ioc.ioc_tags = ""

            if tag not in ioc.ioc_tags.split(","):
                ioc.ioc_tags = f"{ioc.ioc_tags},{tag}".strip(",")
                self.log.info(f"Tag '{tag}' added to IOC #{ioc.ioc_id}")

        except Exception as e:
            self.log.error(
                f"Error writing to IOC: {e}\n"
                f"{traceback.format_exc()}"
            )

    def _build_html_report(self, verdict):
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
                <div class="card-header collapsed"
                     id="drop_raw_enrich"
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