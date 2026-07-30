import os

from iris_enrichment_module.feeds.abuseipdb import lookup_ip as abip_lookup
from iris_enrichment_module.feeds.virustotal import lookup_ip as vt_ip
from iris_enrichment_module.feeds.virustotal import lookup_domain, lookup_hash
from iris_enrichment_module.feeds.urlhaus import lookup_host, lookup_url
from iris_enrichment_module.feeds.malwarebazaar import lookup_hash as mb_hash
from iris_enrichment_module.feeds.nvd import lookup_cve
from iris_enrichment_module.feeds.emailrep import lookup_email as emailrep_lookup
from iris_enrichment_module.feeds.abstractapi_email import lookup_email as abstractapi_lookup
from iris_enrichment_module.verdict import make_verdict
from iris_enrichment_module.cache import cache

# Keys are read from environment variables so nothing sensitive is
# hardcoded in this file. Set these in your shell before running:
#   export ABUSEIPDB_KEY=...
#   export VT_KEY=...
#   export MB_KEY=...
#   export URLHAUS_KEY=...
#   export EMAILREP_KEY=...       (optional — works keyless too)
#   export ABSTRACTAPI_KEY=...
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")
VT_KEY = os.environ.get("VT_KEY")
MB_KEY = os.environ.get("MB_KEY")
URLHAUS_KEY = os.environ.get("URLHAUS_KEY")
EMAILREP_KEY = os.environ.get("EMAILREP_KEY")
ABSTRACTAPI_KEY = os.environ.get("ABSTRACTAPI_KEY")


print("=== AbuseIPDB ===")
print(abip_lookup("185.220.101.47", ABUSEIPDB_KEY))

print("\n=== VirusTotal IP ===")
print(vt_ip("185.220.101.47", VT_KEY))

print("\n=== VirusTotal Domain ===")
print(lookup_domain("malware.wicar.org", VT_KEY))

print("\n=== URLhaus Host ===")
print(lookup_host("185.220.101.47", URLHAUS_KEY))

print("\n=== MalwareBazaar Hash ===")
# Known Emotet hash
print(mb_hash("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d", MB_KEY))

print("\n=== NVD CVE ===")
print(lookup_cve("CVE-2021-44228"))

print("\n=== URLhaus URL lookup ===")
result = lookup_url(
    "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401IYHS198RS/ILoveYou.exe",
    URLHAUS_KEY
)
for k, v in result.items():
    print(f"  {k}: {v}")

print("\n=== URLhaus Domain lookup ===")
result = lookup_host("sskymedia.com", URLHAUS_KEY)
for k, v in result.items():
    print(f"  {k}: {v}")

print("\n=== EmailRep (works keyless too) ===")
print(emailrep_lookup("bill@microsoft.com", EMAILREP_KEY))

print("\n=== AbstractAPI Email Reputation ===")
print(abstractapi_lookup("bill@microsoft.com", ABSTRACTAPI_KEY))


print("\n=== VERDICT TEST 1 — Malicious IP ===")
mock_results = [
    {
        "source": "AbuseIPDB", "score": 100, "total_reports": 91,
        "country": "DE", "isp": "Network for Tor-Exit traffic.",
        "domain": "for-privacy.net", "is_tor": True,
        "usage_type": "Commercial", "last_reported": "2026-07-08T21:01:53+00:00"
    },
    {
        "source": "VirusTotal", "score": 14, "malicious": 13, "suspicious": 3,
        "harmless": 46, "total": 91, "reputation": -21, "country": "DE",
        "as_owner": "Stiftung Erneuerbare Freiheit", "tags": ["tor"]
    }
]
v = make_verdict(mock_results, "ip-any", "185.220.101.47")
print(f"  Verdict: {v['verdict']}")
print(f"  Score: {v['score']}")
print(f"  Sources: {v['feed_sources']}")
print(f"  Malicious count: {v['malicious_count']}")
print(f"  Tags: {v['tags']}")
print(f"  Is Tor: {v['is_tor']}")

print("\n=== VERDICT TEST 2 — Clean IP ===")
mock_clean = [
    {
        "source": "AbuseIPDB", "score": 0, "total_reports": 0, "country": "US",
        "isp": "Google LLC", "domain": "google.com", "is_tor": False,
        "usage_type": "Data Center/Web Hosting/Transit", "last_reported": None
    },
    {
        "source": "VirusTotal", "score": 0, "malicious": 0, "suspicious": 0,
        "harmless": 80, "total": 91, "reputation": 211,
        "country": "US", "as_owner": "Google LLC", "tags": []
    }
]
v2 = make_verdict(mock_clean, "ip-any", "8.8.8.8")
print(f"  Verdict: {v2['verdict']}")
print(f"  Score: {v2['score']}")

print("\n=== VERDICT TEST 3 — All feeds failed ===")
mock_errors = [
    {"error": "timeout", "source": "AbuseIPDB"},
    {"error": "rate_limit_exceeded", "source": "VirusTotal"}
]
v3 = make_verdict(mock_errors, "ip-any", "1.2.3.4")
print(f"  Verdict: {v3['verdict']}")
print(f"  Raw detail: {v3['raw_detail']}")

print("\n=== VERDICT TEST 4 — URLhaus found malware URL ===")
mock_url = [
    {
        "source": "VirusTotal", "score": 85, "malicious": 12, "suspicious": 2,
        "harmless": 60, "total": 91, "final_url": "http://evil.ru/payload.exe",
        "title": "unknown", "tags": ["malware"]
    },
    {
        "source": "URLhaus", "found": True, "url_status": "online",
        "threat": "malware_download", "tags": ["emotet"],
        "date_added": "2024-01-19 01:33:26 UTC"
    }
]
v4 = make_verdict(mock_url, "url", "http://evil.ru/payload.exe")
print(f"  Verdict: {v4['verdict']}")
print(f"  Tags: {v4['tags']}")
print(f"  Score: {v4['score']}")


print("\n=== CACHE TEST ===")
test_verdict = {"verdict": "MALICIOUS", "score": 100}
cache.set("185.220.101.47", test_verdict)
print(f"  Cache size after set: {cache.size()}")

result = cache.get("185.220.101.47")
print(f"  Retrieved verdict: {result['verdict']}")

miss = cache.get("1.2.3.4")
print(f"  Unknown key returns: {miss}")

cache.invalidate("185.220.101.47")
after_invalidate = cache.get("185.220.101.47")
print(f"  After invalidate returns: {after_invalidate}")

print("  Cache working correctly.")