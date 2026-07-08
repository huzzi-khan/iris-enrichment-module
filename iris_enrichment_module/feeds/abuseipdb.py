import requests
from iris_enrichment_module.config_loader import config

BASE_URL = "https://api.abuseipdb.com/api/v2"

def lookup_ip(ip_address):
    """
    Query AbuseIPDB for an IP address.
    Always returns a dict — never raises an exception.
    """
    if not config.feed_enabled("abuseipdb"):
        return {"error": "feed_disabled", "source": "AbuseIPDB"}

    api_key = config.feed_api_key("abuseipdb")
    if not api_key:
        return {"error": "no_api_key", "source": "AbuseIPDB"}

    timeout = config.feed_timeout("abuseipdb")
    max_age = config.feed("abuseipdb").get("max_age_days", 90)

    for attempt in range(1, config.retry_max_attempts + 1):
        try:
            response = requests.get(
                f"{BASE_URL}/check",
                headers={
                    "Key": api_key,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": max_age,
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
                if attempt < config.retry_max_attempts:
                    import time
                    time.sleep(config.retry_delay)
                    continue
                return {"error": f"http_{response.status_code}", "source": "AbuseIPDB"}

        except requests.Timeout:
            if attempt < config.retry_max_attempts:
                import time
                time.sleep(config.retry_delay)
                continue
            return {"error": "timeout", "source": "AbuseIPDB"}
        except Exception as e:
            return {"error": str(e), "source": "AbuseIPDB"}