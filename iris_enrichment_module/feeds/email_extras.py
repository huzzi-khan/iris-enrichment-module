import requests
import dns.resolver

KICKBOX_URL = "https://open.kickbox.com/v1/disposable"


def _extract_domain(email_address):
    if "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[-1].strip().lower()


def _check_disposable(domain, timeout=10):
    try:
        response = requests.get(
            f"{KICKBOX_URL}/{domain}",
            headers={"User-Agent": "iris-enrichment-module"},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json()
            return {"disposable": bool(data.get("disposable", False))}
        return {"error": f"http_{response.status_code}"}
    except requests.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def _check_mx(domain, timeout=10):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        return {"valid_mx": len(answers) > 0}
    except dns.resolver.NXDOMAIN:
        return {"valid_mx": False, "domain_exists": False}
    except dns.resolver.NoAnswer:
        return {"valid_mx": False, "domain_exists": True}
    except Exception as e:
        return {"error": str(e)}


def lookup_email_extras(email_address, timeout=10):
    """
    Keyless supplementary checks for email IOCs:
    - disposable/temp-mail domain check (Kickbox, open API)
    - MX record validity (pure DNS, no external API)
    No API key required for either check.
    """
    domain = _extract_domain(email_address)
    if not domain:
        return {"error": "invalid_email_format", "source": "EmailExtras"}

    disposable_result = _check_disposable(domain, timeout)
    mx_result = _check_mx(domain, timeout)

    if "error" in disposable_result and "error" in mx_result:
        return {
            "error": f"disposable_check: {disposable_result['error']}; "
                     f"mx_check: {mx_result['error']}",
            "source": "EmailExtras"
        }

    is_disposable = disposable_result.get("disposable", False)
    valid_mx = mx_result.get("valid_mx", True)
    domain_exists = mx_result.get("domain_exists", True)

    # Score: baseline low (20) unless a real red flag is found.
    # Kept intentionally low-weight relative to EmailRep so this
    # only tips the verdict when it finds something concrete.
    score = 20
    if is_disposable:
        score = max(score, 75)
    if not domain_exists:
        score = max(score, 85)
    elif not valid_mx:
        score = max(score, 65)

    return {
        "source": "EmailExtras",
        "score": score,
        "disposable": is_disposable,
        "valid_mx": valid_mx,
        "domain_exists": domain_exists,
    }