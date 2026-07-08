import requests
from iris_enrichment_module.config_loader import config

BASE_URL = "https://urlhaus-api.abuse.ch/v1"

def _auth_header():
    key = config.feed_api_key("urlhaus")
    return {"Auth-Key": key} if key else {}

def lookup_host(host):
    """Lookup an IP or domain in URLhaus."""
    if not config.feed_enabled("urlhaus"):
        return {"error": "feed_disabled", "source": "URLhaus"}
    try:
        response = requests.post(
            f"{BASE_URL}/host/",
            headers=_auth_header(),
            data={"host": host},
            timeout=config.feed_timeout("urlhaus")
        )
        if response.status_code == 200:
            data = response.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {
                    "source": "URLhaus",
                    "found": False,
                    "url_count": 0,
                    "malware_urls": []
                }
            urls = data.get("urls", [])
            malware_urls = [
                u.get("url") for u in urls
                if u.get("url_status") == "online"
            ]
            return {
                "source": "URLhaus",
                "found": len(urls) > 0,
                "url_count": len(urls),
                "malware_urls": malware_urls[:5],
            }
        elif response.status_code == 401:
            return {"error": "invalid_api_key", "source": "URLhaus"}
        return {"error": f"http_{response.status_code}", "source": "URLhaus"}
    except requests.Timeout:
        return {"error": "timeout", "source": "URLhaus"}
    except Exception as e:
        return {"error": str(e), "source": "URLhaus"}

def lookup_url(url):
    """Lookup a full URL in URLhaus."""
    if not config.feed_enabled("urlhaus"):
        return {"error": "feed_disabled", "source": "URLhaus"}
    try:
        response = requests.post(
            f"{BASE_URL}/url/",
            headers=_auth_header(),
            data={"url": url},
            timeout=config.feed_timeout("urlhaus")
        )
        if response.status_code == 200:
            data = response.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {"source": "URLhaus", "found": False}
            return {
                "source": "URLhaus",
                "found": True,
                "url_status": data.get("url_status", "unknown"),
                "threat": data.get("threat", "unknown"),
                "tags": data.get("tags", []),
                "date_added": data.get("date_added", "unknown"),
            }
        return {"error": f"http_{response.status_code}", "source": "URLhaus"}
    except Exception as e:
        return {"error": str(e), "source": "URLhaus"}