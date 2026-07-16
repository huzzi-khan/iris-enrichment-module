import datetime


def make_verdict(feed_results, ioc_type, ioc_value,
                  malicious_threshold=80, suspicious_threshold=60):
    """
    Takes a list of raw feed result dicts and produces
    one clean structured verdict dict.

    malicious_threshold / suspicious_threshold are configurable via the
    IRIS admin UI (module_configuration) and passed in by the caller.
    Defaults here match the previous hardcoded values and are only used
    as a fallback if the caller doesn't supply them.
    """
    good_results = [r for r in feed_results if "error" not in r]
    error_results = [r for r in feed_results if "error" in r]

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

    scores = []
    for r in good_results:
        if "score" in r:
            scores.append(r["score"])
        elif r.get("found") is True:
            scores.append(50)
        else:
            scores.append(0)

    highest_score = max(scores) if scores else 0

    try:
        malicious_threshold = float(malicious_threshold)
    except (TypeError, ValueError):
        malicious_threshold = 80

    try:
        suspicious_threshold = float(suspicious_threshold)
    except (TypeError, ValueError):
        suspicious_threshold = 60

    if highest_score >= malicious_threshold:
        verdict = "MALICIOUS"
    elif highest_score >= suspicious_threshold:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    flagged = sum(1 for s in scores if s >= suspicious_threshold)
    total = len(good_results)
    malicious_count = f"{flagged} / {total}"

    good_source_names = [r.get("source", "unknown") for r in good_results]
    if error_results:
        failed = [f"{r['source']}(failed)" for r in error_results]
        all_sources = good_source_names + failed
    else:
        all_sources = good_source_names
    feed_sources = ", ".join(all_sources)

    country = _extract(good_results, "country", "unknown")
    isp = _extract(good_results, ["isp", "as_owner", "holder"], "unknown")
    is_tor = _extract(good_results, "is_tor", False)
    malware_family = _extract(
        good_results, ["malware_family", "popular_threat_name"], "unknown"
    )

    all_tags = []
    for r in good_results:
        tags = r.get("tags", [])
        if isinstance(tags, list):
            all_tags.extend(tags)
        elif isinstance(tags, str) and tags:
            all_tags.append(tags)
    tags_str = ", ".join(list(set(all_tags))) if all_tags else ""

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
    if isinstance(keys, str):
        keys = [keys]
    for r in results:
        for key in keys:
            val = r.get(key)
            if val is not None and val != "unknown" and val != "":
                return val
    return default


def _build_raw_detail(ioc_type, ioc_value, good, errors):
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
            lines.append(f"Malicious vendors: {r['malicious']} / {r.get('total', '?')}")
        if "total_reports" in r:
            lines.append(f"Total reports: {r['total_reports']}")
        if "country" in r:
            lines.append(f"Country: {r['country']}")
        if "isp" in r:
            lines.append(f"ISP: {r['isp']}")
        if "as_owner" in r:
            lines.append(f"AS Owner: {r['as_owner']}")
        if "holder" in r:
            lines.append(f"AS Holder: {r['holder']}")
        if "asn" in r:
            lines.append(f"ASN: {r['asn']}")
        if "announced" in r:
            lines.append(f"Announced: {r['announced']}")
        if "is_tor" in r:
            lines.append(f"Tor exit node: {r['is_tor']}")
        if "malware_family" in r:
            lines.append(f"Malware family: {r['malware_family']}")
        if "cvss_score" in r:
            lines.append(f"CVSS Score: {r['cvss_score']} ({r.get('severity', '?')})")
        if "description" in r:
            lines.append(f"Description: {r['description'][:200]}")
        if r.get("found") is True and "url_count" in r:
            lines.append(f"Malware URLs hosted: {r['url_count']}")
        if r.get("tags"):
            t = r["tags"]
            if isinstance(t, list):
                lines.append(f"Tags: {', '.join(t)}")
        lines.append("")
    if errors:
        lines.append("--- Failed sources ---")
        for r in errors:
            lines.append(f"{r['source']}: {r['error']}")
    return "\n".join(lines)


def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")