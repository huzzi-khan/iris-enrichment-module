import requests

BASE_URL = "https://emailreputation.abstractapi.com/v1/"


def lookup_email(email_address, api_key, timeout=10):
    if not api_key:
        return {"error": "no_api_key", "source": "AbstractAPI"}
    try:
        response = requests.get(
            BASE_URL,
            params={"api_key": api_key, "email": email_address},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json()

            deliverability = data.get("email_deliverability") or {}
            quality = data.get("email_quality") or {}
            risk = data.get("email_risk") or {}
            breaches = data.get("email_breaches") or {}
            domain = data.get("email_domain") or {}

            address_risk = risk.get("address_risk_status", "unknown")
            domain_risk = risk.get("domain_risk_status", "unknown")
            total_breaches = breaches.get("total_breaches", 0) or 0

            # Base score off AbstractAPI's own risk categorization
            risk_score_map = {"high": 85, "medium": 55, "low": 15, "unknown": 40}
            score = risk_score_map.get(address_risk, 40)

            # Escalate for concrete red flags even if risk_status is lenient
            if quality.get("is_disposable"):
                score = max(score, 80)
            if deliverability.get("status") == "undeliverable":
                score = max(score, 60)
            if domain.get("is_risky_tld"):
                score = max(score, 70)
            if total_breaches >= 50:
                score = max(score, 65)

            return {
                "source": "AbstractAPI",
                "score": score,
                "address_risk_status": address_risk,
                "domain_risk_status": domain_risk,
                "deliverability_status": deliverability.get("status", "unknown"),
                "is_disposable": quality.get("is_disposable", False),
                "is_free_email": quality.get("is_free_email", False),
                "is_role": quality.get("is_role", False),
                "is_catchall": quality.get("is_catchall", False),
                "total_breaches": total_breaches,
                "date_first_breached": breaches.get("date_first_breached"),
                "date_last_breached": breaches.get("date_last_breached"),
                "domain_age_days": domain.get("domain_age"),
                "is_risky_tld": domain.get("is_risky_tld", False),
            }
        elif response.status_code == 401:
            return {"error": "invalid_api_key", "source": "AbstractAPI"}
        elif response.status_code == 422:
            return {"error": "invalid_email_format", "source": "AbstractAPI"}
        elif response.status_code == 429:
            return {"error": "rate_limit_exceeded", "source": "AbstractAPI"}
        return {"error": f"http_{response.status_code}", "source": "AbstractAPI"}
    except requests.Timeout:
        return {"error": "timeout", "source": "AbstractAPI"}
    except Exception as e:
        return {"error": str(e), "source": "AbstractAPI"}