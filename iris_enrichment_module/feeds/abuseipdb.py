import requests

BASE_URL = "https://api.abuseipdb.com/api/v2"

def lookup_ip(ip_address, api_key, max_age_days=90, timeout=10):
    """
    Query AbuseIPDB for an IP address.
    API key passed as parameter — not read from config file.
    """
    if not api_key:
        return {"error": "no_api_key", "source": "AbuseIPDB"}

    for attempt in range(1, 3):
        try:
            response = requests.get(
                f"{BASE_URL}/check",
                headers={
                    "Key": api_key,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": max_age_days,
                    "verbose": True
                },
                timeout=timeout
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "source": "AbuseIPDB",
                    "score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "domain": data.get("domain", "unknown"),
                    "is_tor": data.get("isTor", False),
                    "usage_type": data.get("usageType", "unknown"),
                    "last_reported": data.get("lastReportedAt", "unknown"),
                }
            elif response.status_code == 401:
                return {"error": "invalid_api_key", "source": "AbuseIPDB"}
            elif response.status_code == 422:
                return {"error": "invalid_ip_format", "source": "AbuseIPDB"}
            elif response.status_code == 429:
                return {"error": "rate_limit_exceeded", "source": "AbuseIPDB"}
            else:
                if attempt < 2:
                    import time
                    time.sleep(10)
                    continue
                return {"error": f"http_{response.status_code}", "source": "AbuseIPDB"}
        except requests.Timeout:
            if attempt < 2:
                import time
                time.sleep(10)
                continue
            return {"error": "timeout", "source": "AbuseIPDB"}
        except Exception as e:
            return {"error": str(e), "source": "AbuseIPDB"}