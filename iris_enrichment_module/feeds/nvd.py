import requests
from iris_enrichment_module.config_loader import config

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def lookup_cve(cve_id):
    """Lookup a CVE in NIST NVD."""
    if not config.feed_enabled("nvd"):
        return {"error": "feed_disabled", "source": "NVD"}
    try:
        headers = {}
        api_key = config.feed_api_key("nvd")
        if api_key:
            headers["apiKey"] = api_key

        response = requests.get(
            BASE_URL,
            headers=headers,
            params={"cveId": cve_id.upper()},
            timeout=config.feed_timeout("nvd")
        )
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"source": "NVD", "found": False}
            cve = vulns[0].get("cve", {})
            # Get CVSS score
            metrics = cve.get("metrics", {})
            score = 0
            severity = "unknown"
            # Try CVSSv3 first then v2
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "unknown")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = metrics["cvssMetricV2"][0].get(
                    "baseSeverity", "unknown")
            # Get description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )
            return {
                "source": "NVD",
                "found": True,
                "cve_id": cve.get("id", cve_id),
                "cvss_score": score,
                "severity": severity,
                "description": description[:300],
                "published": cve.get("published", "unknown"),
            }
        elif response.status_code == 404:
            return {"source": "NVD", "found": False}
        return {"error": f"http_{response.status_code}", "source": "NVD"}
    except requests.Timeout:
        return {"error": "timeout", "source": "NVD"}
    except Exception as e:
        return {"error": str(e), "source": "NVD"}