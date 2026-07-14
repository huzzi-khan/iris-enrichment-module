import requests

BASE_URL = "https://urlhaus-api.abuse.ch/v1"

def lookup_host(host, api_key, timeout=10):
    headers = {"Auth-Key": api_key} if api_key else {}
    try:
        response = requests.post(
            f"{BASE_URL}/host/",
            headers=headers,
            data={"host": host},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "no_results":
                return {"source": "URLhaus", "found": False, "url_count": 0, "malware_urls": []}
            urls = data.get("urls", [])
            malware_urls = [u.get("url") for u in urls if u.get("url_status") == "online"]
            return {
                "source": "URLhaus",
                "found": len(urls) > 0,
                "url_count": len(urls),
                "malware_urls": malware_urls[:5],
            }
        return {"error": f"http_{response.status_code}", "source": "URLhaus"}
    except requests.Timeout:
        return {"error": "timeout", "source": "URLhaus"}
    except Exception as e:
        return {"error": str(e), "source": "URLhaus"}

def lookup_url(url, api_key, timeout=10):
    headers = {"Auth-Key": api_key} if api_key else {}
    try:
        response = requests.post(
            f"{BASE_URL}/url/",
            headers=headers,
            data={"url": url},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "no_results":
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