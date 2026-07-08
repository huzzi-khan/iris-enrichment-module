import requests
import base64
from iris_enrichment_module.config_loader import config

BASE_URL = "https://www.virustotal.com/api/v3"

def _headers():
    return {"x-apikey": config.feed_api_key("virustotal")}

def _check_enabled():
    if not config.feed_enabled("virustotal"):
        return {"error": "feed_disabled", "source": "VirusTotal"}
    if not config.feed_api_key("virustotal"):
        return {"error": "no_api_key", "source": "VirusTotal"}
    return None

def _get(url):
    """Shared GET with retry logic."""
    timeout = config.feed_timeout("virustotal")
    for attempt in range(1, config.retry_max_attempts + 1):
        try:
            response = requests.get(url, headers=_headers(), timeout=timeout)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {"error": "invalid_api_key", "source": "VirusTotal"}
            elif response.status_code == 404:
                return {"error": "not_found", "source": "VirusTotal"}
            elif response.status_code == 429:
                return {"error": "rate_limit_exceeded", "source": "VirusTotal"}
            else:
                if attempt < config.retry_max_attempts:
                    import time
                    time.sleep(config.retry_delay)
                    continue
                return {"error": f"http_{response.status_code}", "source": "VirusTotal"}
        except requests.Timeout:
            if attempt < config.retry_max_attempts:
                import time
                time.sleep(config.retry_delay)
                continue
            return {"error": "timeout", "source": "VirusTotal"}
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}

def lookup_ip(ip):
    err = _check_enabled()
    if err: return err
    raw = _get(f"{BASE_URL}/ip_addresses/{ip}")
    if "error" in raw: return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "unknown"),
        "as_owner": attrs.get("as_owner", "unknown"),
        "tags": attrs.get("tags", []),
    }

def lookup_domain(domain):
    err = _check_enabled()
    if err: return err
    raw = _get(f"{BASE_URL}/domains/{domain}")
    if "error" in raw: return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "registrar": attrs.get("registrar", "unknown"),
        "tags": attrs.get("tags", []),
    }

def lookup_hash(file_hash):
    err = _check_enabled()
    if err: return err
    raw = _get(f"{BASE_URL}/files/{file_hash}")
    if "error" in raw: return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "file_type": attrs.get("type_description", "unknown"),
        "size": attrs.get("size", 0),
        "names": attrs.get("names", []),
        "tags": attrs.get("tags", []),
        "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
    }

def lookup_url(url):
    err = _check_enabled()
    if err: return err
    # VT requires URL to be base64 encoded
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    raw = _get(f"{BASE_URL}/urls/{url_id}")
    if "error" in raw: return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "final_url": attrs.get("last_final_url", url),
        "title": attrs.get("title", "unknown"),
        "tags": attrs.get("tags", []),
    }