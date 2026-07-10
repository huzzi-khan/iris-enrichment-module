import requests
from iris_enrichment_module.config_loader import config

BASE_URL = "https://stat.ripe.net/data/as-overview/data.json"

def lookup_asn(asn_value):
    """
    Lookup ASN information from RIPE NCC Stat.
    No API key required.
    """
    try:
        # Clean the ASN value — remove AS prefix if present
        asn = asn_value.upper().replace("AS", "").strip()

        response = requests.get(
            BASE_URL,
            params={"resource": f"AS{asn}"},
            timeout=15
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            holder = data.get("holder", "unknown")
            announced = data.get("announced", False)
            return {
                "source": "RIPE NCC",
                "score": 0,
                "asn": f"AS{asn}",
                "holder": holder,
                "announced": announced,
                "found": True
            }
        return {
            "error": f"http_{response.status_code}",
            "source": "RIPE NCC"
        }
    except requests.Timeout:
        return {"error": "timeout", "source": "RIPE NCC"}
    except Exception as e:
        return {"error": str(e), "source": "RIPE NCC"}