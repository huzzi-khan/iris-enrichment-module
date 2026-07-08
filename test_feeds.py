from iris_enrichment_module.feeds.abuseipdb import lookup_ip as abip_lookup
from iris_enrichment_module.feeds.virustotal import lookup_ip as vt_ip
from iris_enrichment_module.feeds.virustotal import lookup_domain, lookup_hash
from iris_enrichment_module.feeds.urlhaus import lookup_host
from iris_enrichment_module.feeds.malwarebazaar import lookup_hash as mb_hash
from iris_enrichment_module.feeds.nvd import lookup_cve

print("=== AbuseIPDB ===")
print(abip_lookup("185.220.101.47"))

print("\n=== VirusTotal IP ===")
print(vt_ip("185.220.101.47"))

print("\n=== VirusTotal Domain ===")
print(lookup_domain("malware.wicar.org"))

print("\n=== URLhaus Host ===")
print(lookup_host("185.220.101.47"))

#print("\n=== MalwareBazaar Hash ===")
# Known Emotet hash
#print(mb_hash("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"))

print("\n=== NVD CVE ===")
print(lookup_cve("CVE-2021-44228"))

from iris_enrichment_module.feeds.urlhaus import lookup_url, lookup_host

print("\n=== URLhaus URL lookup ===")
# Known malicious URL from URLhaus documentation
result = lookup_url(
    "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401IYHS198RS/ILoveYou.exe"
)
for k, v in result.items():
    print(f"  {k}: {v}")

print("\n=== URLhaus Domain lookup ===")
# Known malicious domain
result = lookup_host("sskymedia.com")
for k, v in result.items():
    print(f"  {k}: {v}")