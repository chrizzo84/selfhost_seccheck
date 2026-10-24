"""Runtime configuration via environment variables."""

from __future__ import annotations

import os
from pathlib import Path

import certifi


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Refuse targets that resolve to private, loopback or link-local addresses.
# Off by default because self-hosted instances often live in the LAN; turn it
# on when the scanner itself is reachable from the internet.
BLOCK_PRIVATE_TARGETS = _bool("SECCHECK_BLOCK_PRIVATE", False)

CHECK_TIMEOUT = float(os.getenv("SECCHECK_CHECK_TIMEOUT", "30"))
HTTP_TIMEOUT = float(os.getenv("SECCHECK_HTTP_TIMEOUT", "10"))
CONCURRENCY = int(os.getenv("SECCHECK_CONCURRENCY", "8"))

# CA bundle used to decide whether a certificate chain is trusted. Point it at
# a bundle that includes your internal CA if you run one.
CA_BUNDLE = os.getenv("SECCHECK_CA_BUNDLE") or certifi.where()

# Optional, raises the GitHub API rate limit for release and advisory lookups.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Optional NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key):
# 50 instead of 5 requests per 30 seconds.
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Hours between two updates of the CVE feed; 0 updates it only on request.
CVE_SYNC_HOURS = float(os.getenv("SECCHECK_CVE_SYNC_HOURS", "2"))

USER_AGENT = "SelfHostSecCheck/0.1"

# Scan history, targets and settings (SQLite).
DATA_DIR = Path(os.getenv("SECCHECK_DATA_DIR") or Path(__file__).resolve().parent.parent / "data")

# Language when the client does not ask for one (en, de).
DEFAULT_LANGUAGE = os.getenv("SECCHECK_LANG", "en").strip().lower() or "en"

# Run scheduled scans inside the web server process.
SCHEDULER_ENABLED = _bool("SECCHECK_SCHEDULER", True)
