import requests

BASE_URL = "https://emailrep.io"

def lookup_email(email_address, api_key=None, timeout=10):
    headers = {"User-Agent": "iris-enrichment-module"}
    if api_key:
        headers["Key"] = api_key
    try:
        response = requests.get(
            f"{BASE_URL}/{email_address}",
            headers=headers,
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json()
            reputation = data.get("reputation", "none")
            score_map = {"high": 10, "medium": 30, "low": 70, "none": 50}
            score = score_map.get(reputation, 50)
            suspicious = data.get("suspicious", False)
            if suspicious:
                score = max(score, 70)
            details = data.get("details", {})
            return {
                "source": "EmailRep",
                "score": score,
                "reputation": reputation,
                "suspicious": suspicious,
                "blacklisted": details.get("blacklisted", False),
                "malicious_activity": details.get("malicious_activity", False),
                "spam": details.get("spam", False),
                "authenticated": bool(api_key),
            }
        elif response.status_code == 401:
            return {"error": "invalid_api_key", "source": "EmailRep"}
        elif response.status_code == 403:
            return {"error": "missing_or_blocked_user_agent", "source": "EmailRep"}
        elif response.status_code == 429:
            return {"error": "rate_limit_exceeded", "source": "EmailRep"}
        return {"error": f"http_{response.status_code}", "source": "EmailRep"}
    except requests.Timeout:
        return {"error": "timeout", "source": "EmailRep"}
    except Exception as e:
        return {"error": str(e), "source": "EmailRep"}