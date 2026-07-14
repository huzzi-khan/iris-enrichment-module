import requests

BASE_URL = "https://stat.ripe.net/data/as-overview/data.json"

def lookup_asn(asn_value, api_key=None, timeout=15):
    try:
        asn = asn_value.upper().replace("AS", "").strip()
        response = requests.get(
            BASE_URL,
            params={"resource": f"AS{asn}"},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "RIPE NCC",
                "score": 0,
                "asn": f"AS{asn}",
                "holder": data.get("holder", "unknown"),
                "announced": data.get("announced", False),
                "found": True
            }
        return {"error": f"http_{response.status_code}", "source": "RIPE NCC"}
    except requests.Timeout:
        return {"error": "timeout", "source": "RIPE NCC"}
    except Exception as e:
        return {"error": str(e), "source": "RIPE NCC"}