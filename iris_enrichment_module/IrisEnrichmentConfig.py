module_name = "IrisEnrichmentModule"
module_description = (
    "Automated IOC enrichment via AbuseIPDB, VirusTotal, "
    "URLhaus, MalwareBazaar, EmailRep, and NIST NVD. "
    "Developed by Cydea Tech."
)
interface_version = "1.2.0"
module_version = "1.0.0"
pipeline_support = False
pipeline_info = {}

module_configuration = [

    # ── API Keys ──────────────────────────────────────────
    {
        "param_name": "abuseipdb_api_key",
        "param_human_name": "AbuseIPDB API Key",
        "param_description": "API key for AbuseIPDB — used for IP address enrichment",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "virustotal_api_key",
        "param_human_name": "VirusTotal API Key",
        "param_description": "API key for VirusTotal — used for IP, domain, hash, and URL enrichment",
        "default": None,
        "mandatory": False,
        "type": "sensitive_string"
    },
    {
        "param_name": "urlhaus_api_key",
        "param_human_name": "URLhaus / abuse.ch Auth Key",
        "param_description": "Auth key from auth.abuse.ch — used for URL and domain enrichment",
        "default": None,
        "mandatory": False,
        "type": "sensitive_string"
    },
    {
        "param_name": "malwarebazaar_api_key",
        "param_human_name": "MalwareBazaar Auth Key",
        "param_description": "Same abuse.ch Auth key — used for file hash enrichment",
        "default": None,
        "mandatory": False,
        "type": "sensitive_string"
    },
    {
        "param_name": "emailrep_api_key",
        "param_human_name": "EmailRep API Key",
        "param_description": "Optional API key for EmailRep.io — improves rate limits. Email enrichment works without one. Request a free key at https://emailrep.io/key",
        "default": None,
        "mandatory": False,
        "type": "sensitive_string"
    },
    {
        "param_name": "nvd_api_key",
        "param_human_name": "NIST NVD API Key",
        "param_description": "Optional API key for NIST NVD — improves rate limits for CVE enrichment",
        "default": None,
        "mandatory": False,
        "type": "sensitive_string"
    },

    # ── Triggers ──────────────────────────────────────────
    {
        "param_name": "auto_trigger_on_create",
        "param_human_name": "Auto trigger on IOC create",
        "param_description": "Automatically enrich every IOC when it is added to a case",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "auto_trigger_on_update",
        "param_human_name": "Auto trigger on IOC update",
        "param_description": "Re-enrich an IOC whenever it is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "manual_trigger_enabled",
        "param_human_name": "Enable manual trigger",
        "param_description": "Allow analysts to manually trigger enrichment on individual IOCs",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },

    # ── Verdict Thresholds ────────────────────────────────
    {
        "param_name": "malicious_threshold",
        "param_human_name": "Malicious threshold",
        "param_description": "Score at or above this value is classified as MALICIOUS (0-100)",
        "default": "80",
        "mandatory": True,
        "type": "float",
        "section": "Verdict"
    },
    {
        "param_name": "suspicious_threshold",
        "param_human_name": "Suspicious threshold",
        "param_description": "Score at or above this value is classified as SUSPICIOUS (0-100)",
        "default": "60",
        "mandatory": True,
        "type": "float",
        "section": "Verdict"
    },

    # ── Feed Toggles ──────────────────────────────────────
    {
        "param_name": "abuseipdb_enabled",
        "param_human_name": "Enable AbuseIPDB",
        "param_description": "Enable or disable AbuseIPDB as an enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "virustotal_enabled",
        "param_human_name": "Enable VirusTotal",
        "param_description": "Enable or disable VirusTotal as an enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "urlhaus_enabled",
        "param_human_name": "Enable URLhaus",
        "param_description": "Enable or disable URLhaus as an enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "malwarebazaar_enabled",
        "param_human_name": "Enable MalwareBazaar",
        "param_description": "Enable or disable MalwareBazaar as an enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "emailrep_enabled",
        "param_human_name": "Enable EmailRep",
        "param_description": "Enable or disable EmailRep as an enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "nvd_enabled",
        "param_human_name": "Enable NIST NVD",
        "param_description": "Enable or disable NIST NVD as a CVE enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },
    {
        "param_name": "ripe_enabled",
        "param_human_name": "Enable RIPE NCC",
        "param_description": "Enable or disable RIPE NCC as an ASN enrichment source",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Feeds"
    },

    # ── Cache ─────────────────────────────────────────────
    {
        "param_name": "cache_enabled",
        "param_human_name": "Enable result cache",
        "param_description": "Cache enrichment results to avoid querying the same IOC twice",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Cache"
    },
    {
        "param_name": "cache_ttl_hours",
        "param_human_name": "Cache TTL in hours",
        "param_description": "How many hours to keep cached results before re-querying",
        "default": "24",
        "mandatory": True,
        "type": "float",
        "section": "Cache"
    },
]