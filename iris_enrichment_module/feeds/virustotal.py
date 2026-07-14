import requests
import base64

BASE_URL = "https://www.virustotal.com/api/v3"

def _get(url, api_key, timeout=15):
    for attempt in range(1, 3):
        try:
            response = requests.get(
                url,
                headers={"x-apikey": api_key},
                timeout=timeout
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {"error": "invalid_api_key", "source": "VirusTotal"}
            elif response.status_code == 404:
                return {"error": "not_found", "source": "VirusTotal"}
            elif response.status_code == 429:
                return {"error": "rate_limit_exceeded", "source": "VirusTotal"}
            else:
                if attempt < 2:
                    import time
                    time.sleep(10)
                    continue
                return {"error": f"http_{response.status_code}", "source": "VirusTotal"}
        except requests.Timeout:
            if attempt < 2:
                import time
                time.sleep(10)
                continue
            return {"error": "timeout", "source": "VirusTotal"}
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}

def lookup_ip(ip, api_key, timeout=15):
    if not api_key:
        return {"error": "no_api_key", "source": "VirusTotal"}
    raw = _get(f"{BASE_URL}/ip_addresses/{ip}", api_key, timeout)
    if "error" in raw:
        return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 1
    return {
        "source": "VirusTotal",
        "score": round((stats.get("malicious", 0) / total) * 100),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "unknown"),
        "as_owner": attrs.get("as_owner", "unknown"),
        "tags": attrs.get("tags", []),
    }

def lookup_domain(domain, api_key, timeout=15):
    if not api_key:
        return {"error": "no_api_key", "source": "VirusTotal"}
    raw = _get(f"{BASE_URL}/domains/{domain}", api_key, timeout)
    if "error" in raw:
        return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 1
    return {
        "source": "VirusTotal",
        "score": round((stats.get("malicious", 0) / total) * 100),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "registrar": attrs.get("registrar", "unknown"),
        "tags": attrs.get("tags", []),
    }

def lookup_hash(file_hash, api_key, timeout=15):
    if not api_key:
        return {"error": "no_api_key", "source": "VirusTotal"}
    raw = _get(f"{BASE_URL}/files/{file_hash}", api_key, timeout)
    if "error" in raw:
        return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 1
    return {
        "source": "VirusTotal",
        "score": round((stats.get("malicious", 0) / total) * 100),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "file_type": attrs.get("type_description", "unknown"),
        "size": attrs.get("size", 0),
        "names": attrs.get("names", []),
        "tags": attrs.get("tags", []),
        "popular_threat_name": attrs.get(
            "popular_threat_classification", {}
        ).get("suggested_threat_label", "unknown"),
    }

def lookup_url(url, api_key, timeout=15):
    if not api_key:
        return {"error": "no_api_key", "source": "VirusTotal"}
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")
    raw = _get(f"{BASE_URL}/urls/{url_id}", api_key, timeout)
    if "error" in raw:
        return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 1
    return {
        "source": "VirusTotal",
        "score": round((stats.get("malicious", 0) / total) * 100),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
        "final_url": attrs.get("last_final_url", url),
        "title": attrs.get("title", "unknown"),
        "tags": attrs.get("tags", []),
    }