import datetime
from iris_enrichment_module.config_loader import config


def make_verdict(feed_results, ioc_type, ioc_value):
    """
    Takes a list of raw feed result dicts and produces
    one clean structured verdict dict.

    feed_results: list of dicts returned by feed clients
    ioc_type: string like 'ip-any', 'domain', 'md5' etc
    ioc_value: the actual IOC value string

    Returns a clean verdict dict ready to write to IRIS
    custom attributes.
    """

    # Separate good results from errors
    good_results = [r for r in feed_results if "error" not in r]
    error_results = [r for r in feed_results if "error" in r]

    # If every feed failed return an error verdict
    if not good_results:
        errors = ", ".join([
            f"{r['source']}: {r['error']}"
            for r in error_results
        ])
        return {
            "verdict": "ERROR",
            "score": 0,
            "malicious_count": "0 / 0",
            "feed_sources": "none",
            "country": "unknown",
            "isp": "unknown",
            "is_tor": False,
            "tags": "",
            "malware_family": "unknown",
            "raw_detail": f"All feeds failed: {errors}",
            "enrichment_date": _now()
        }

    # ── Compute score ─────────────────────────────────────
    # Each feed returns a score 0-100.
    # We take the highest score across all good results.
    # A feed that returns found:False scores 0.
    # A feed that returns found:True with no score scores 50
    # as a conservative signal.

    scores = []
    for r in good_results:
        if "score" in r:
            scores.append(r["score"])
        elif r.get("found") is True:
            # URLhaus or MalwareBazaar found something but
            # has no numeric score — treat as suspicious
            scores.append(50)
        else:
            scores.append(0)

    highest_score = max(scores) if scores else 0

    # ── Apply thresholds ──────────────────────────────────
    malicious_threshold = config.malicious_threshold
    suspicious_threshold = config.suspicious_threshold

    if highest_score >= malicious_threshold:
        verdict = "MALICIOUS"
    elif highest_score >= suspicious_threshold:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # ── Count how many sources flagged it ─────────────────
    flagged = sum(
        1 for s in scores
        if s >= suspicious_threshold
    )
    total = len(good_results)
    malicious_count = f"{flagged} / {total}"

    # ── Collect source names ──────────────────────────────
    good_source_names = [r.get("source", "unknown") for r in good_results]
    if error_results:
        failed = [f"{r['source']}(failed)" for r in error_results]
        all_sources = good_source_names + failed
    else:
        all_sources = good_source_names
    feed_sources = ", ".join(all_sources)

    # ── Extract contextual fields ─────────────────────────
    # Pull these from whichever feed returned them.
    # Priority: first good result that has the field.

    country = _extract(good_results, "country", "unknown")
    isp = _extract(good_results, ["isp", "as_owner"], "unknown")
    is_tor = _extract(good_results, "is_tor", False)
    malware_family = _extract(
        good_results, ["malware_family", "popular_threat_name"], "unknown"
    )

    # Collect all tags from all feeds
    all_tags = []
    for r in good_results:
        tags = r.get("tags", [])
        if isinstance(tags, list):
            all_tags.extend(tags)
        elif isinstance(tags, str) and tags:
            all_tags.append(tags)
    tags_str = ", ".join(list(set(all_tags))) if all_tags else ""

    # ── Build raw detail string ───────────────────────────
    raw_detail = _build_raw_detail(
        ioc_type, ioc_value, good_results, error_results
    )

    return {
        "verdict": verdict,
        "score": highest_score,
        "malicious_count": malicious_count,
        "feed_sources": feed_sources,
        "country": str(country),
        "isp": str(isp),
        "is_tor": bool(is_tor),
        "tags": tags_str,
        "malware_family": str(malware_family),
        "raw_detail": raw_detail,
        "enrichment_date": _now()
    }


def _extract(results, keys, default):
    """
    Extract first non-default value from results
    searching for any of the given keys.
    keys can be a string or list of strings.
    """
    if isinstance(keys, str):
        keys = [keys]
    for r in results:
        for key in keys:
            val = r.get(key)
            if val is not None and val != "unknown" and val != "":
                return val
    return default


def _build_raw_detail(ioc_type, ioc_value, good, errors):
    """
    Build a human readable summary string for the
    Raw Detail custom attribute field in IRIS.
    """
    lines = [
        f"IOC: {ioc_value} ({ioc_type})",
        f"Enriched: {_now()}",
        ""
    ]
    for r in good:
        source = r.get("source", "unknown")
        lines.append(f"--- {source} ---")

        if "score" in r:
            lines.append(f"Score: {r['score']} / 100")
        if "malicious" in r:
            lines.append(
                f"Malicious vendors: {r['malicious']} / {r.get('total', '?')}"
            )
        if "total_reports" in r:
            lines.append(f"Total reports: {r['total_reports']}")
        if "country" in r:
            lines.append(f"Country: {r['country']}")
        if "isp" in r:
            lines.append(f"ISP: {r['isp']}")
        if "as_owner" in r:
            lines.append(f"AS Owner: {r['as_owner']}")
        if "is_tor" in r:
            lines.append(f"Tor exit node: {r['is_tor']}")
        if "usage_type" in r:
            lines.append(f"Usage type: {r['usage_type']}")
        if "malware_family" in r:
            lines.append(f"Malware family: {r['malware_family']}")
        if "popular_threat_name" in r:
            lines.append(f"Threat label: {r['popular_threat_name']}")
        if "file_type" in r:
            lines.append(f"File type: {r['file_type']}")
        if "cvss_score" in r:
            lines.append(f"CVSS Score: {r['cvss_score']} ({r.get('severity', '?')})")
        if "description" in r:
            lines.append(f"Description: {r['description'][:200]}")
        if r.get("found") is True and "url_count" in r:
            lines.append(f"Malware URLs hosted: {r['url_count']}")
        if r.get("tags"):
            tags = r["tags"]
            if isinstance(tags, list):
                lines.append(f"Tags: {', '.join(tags)}")
        lines.append("")

    if errors:
        lines.append("--- Failed sources ---")
        for r in errors:
            lines.append(f"{r['source']}: {r['error']}")

    return "\n".join(lines)


def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")