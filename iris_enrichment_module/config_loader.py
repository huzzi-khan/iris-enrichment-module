import yaml
import os

# Default path — sits next to the package root
CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config.yml"
)

class Config:
    """
    Loads and exposes config.yml as a clean object.
    All other files import from here — never read yml directly.
    """

    def __init__(self, path=None):
        self._path = path or CONFIG_PATH
        self._data = self._load()

    def _load(self):
        if not os.path.exists(self._path):
            raise FileNotFoundError(
                f"Config file not found at: {self._path}\n"
                f"Copy config.yml to that path and fill in your API keys."
            )
        with open(self._path, "r") as f:
            data = yaml.safe_load(f)
        self._validate(data)
        return data

    def _validate(self, data):
        required_sections = ["iris", "feeds", "verdicts", "cache", "retry"]
        for section in required_sections:
            if section not in data:
                raise ValueError(
                    f"config.yml is missing required section: '{section}'"
                )

    # ── IRIS ──────────────────────────────────────
    @property
    def iris_url(self):
        return self._data["iris"]["url"].rstrip("/")

    @property
    def iris_api_key(self):
        return self._data["iris"]["api_key"]

    @property
    def iris_verify_ssl(self):
        return self._data["iris"].get("verify_ssl", False)

    # ── FEEDS ─────────────────────────────────────
    def feed(self, name):
        """Returns config dict for a specific feed."""
        return self._data["feeds"].get(name, {})

    def feed_enabled(self, name):
        return self._data["feeds"].get(name, {}).get("enabled", False)

    def feed_api_key(self, name):
        return self._data["feeds"].get(name, {}).get("api_key")

    def feed_timeout(self, name):
        return self._data["feeds"].get(name, {}).get("timeout_seconds", 10)

    # ── VERDICTS ──────────────────────────────────
    @property
    def malicious_threshold(self):
        return self._data["verdicts"].get("malicious_threshold", 80)

    @property
    def suspicious_threshold(self):
        return self._data["verdicts"].get("suspicious_threshold", 60)

    # ── CACHE ─────────────────────────────────────
    @property
    def cache_enabled(self):
        return self._data["cache"].get("enabled", True)

    @property
    def cache_ttl(self):
        return self._data["cache"].get("ttl_seconds", 86400)

    # ── RETRY ─────────────────────────────────────
    @property
    def retry_max_attempts(self):
        return self._data["retry"].get("max_attempts", 2)

    @property
    def retry_delay(self):
        return self._data["retry"].get("retry_delay_seconds", 10)

    # ── LOGGING ───────────────────────────────────
    @property
    def log_level(self):
        return self._data.get("logging", {}).get("level", "INFO")


# Single shared instance imported everywhere
config = Config()