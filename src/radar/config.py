"""Tunable settings: sources, watchlist, and scoring thresholds.

Everything a reviewer might want to change lives here, in plain data.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Generic client name: no personal details in requests to third parties.
USER_AGENT = "IncidentRadar/1.0 (security news aggregator)"
HTTP_TIMEOUT_S = 20.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # the KEV catalog is ~1.5 MB


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    kind: str  # "news" | "vendor" | "gov"


# RSS/Atom feeds. Any one failing is logged and skipped; it never stops a run.
FEEDS: list[Feed] = [
    # Government
    Feed("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "gov"),
    # Security news
    Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    Feed("SecurityWeek", "https://www.securityweek.com/feed/", "news"),
    Feed("Help Net Security", "https://www.helpnetsecurity.com/feed/", "news"),
    Feed("The Record", "https://therecord.media/feed", "news"),
    Feed("Cybersecurity Dive", "https://www.cybersecuritydive.com/feeds/news/", "news"),
    Feed("Krebs on Security", "https://krebsonsecurity.com/feed/", "news"),
    Feed("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml", "news"),
    # Vendor PSIRTs
    Feed("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss", "vendor"),
    Feed(
        "Cisco PSIRT",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "vendor",
    ),
    Feed("Palo Alto Networks", "https://security.paloaltonetworks.com/rss.xml", "vendor"),
    Feed("Fortinet PSIRT", "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "vendor"),
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"

# How far back to look on each run (sources are de-duplicated, so overlap is fine).
KEV_LOOKBACK_DAYS = 14
NVD_LOOKBACK_HOURS = 48
NEWS_MAX_AGE_DAYS = 4
INCIDENT_WINDOW_DAYS = 7  # incidents older than this drop off the dashboard

# Personal watchlist: matches add points and lower the personal alert bar.
WATCHLIST: dict[str, list[str]] = {
    "Web & proxies": ["nginx", "apache http", "httpd", "haproxy", "envoy", "cloudflare", "openssl", "tomcat"],
    "Cloud & containers": [
        "google cloud",
        "gcp",
        "aws",
        "amazon web services",
        "azure",
        "kubernetes",
        "k8s",
        "docker",
        "containerd",
        "runc",
        "terraform",
        "helm",
    ],
    "Identity & email": [
        "okta",
        "entra",
        "azure ad",
        "active directory",
        "microsoft 365",
        "office 365",
        "m365",
        "google workspace",
        "exchange",
        "outlook",
        "sso",
        "oauth",
    ],
    "Edge & VPN": [
        "fortinet",
        "fortigate",
        "fortios",
        "palo alto",
        "pan-os",
        "globalprotect",
        "ivanti",
        "pulse secure",
        "citrix",
        "netscaler",
        "cisco",
        "f5",
        "big-ip",
        "sonicwall",
        "vpn",
    ],
}

# Keyword signals. Matched case-insensitively against titles and summaries.
EXPLOITATION_TERMS = [
    "actively exploited",
    "exploited in the wild",
    "under active exploitation",
    "zero-day",
    "zero day",
    "0-day",
    "mass exploitation",
    "emergency patch",
    "emergency directive",
    "under attack",
]
IMPACT_TERMS = [
    "remote code execution",
    "rce",
    "unauthenticated",
    "wormable",
    "supply chain",
    "supply-chain",
    "ransomware",
    "data breach",
    "takeover",
    "backdoor",
    "authentication bypass",
]
SCALE_TERMS = [
    "millions",
    "massive",
    "global outage",
    "worldwide",
    "nation-state",
    "critical infrastructure",
    "widespread",
    "large-scale",
    "thousands of",
]
POC_TERMS = ["proof-of-concept", "proof of concept", "poc", "poc exploits", "exploit code", "exploit released"]

# Articles that are digests, not events, are skipped entirely.
SKIP_TITLE_TERMS = [
    "week in review",
    "weekly recap",
    "recap",
    "roundup",
    "round-up",
    "podcast",
    "webinar",
    "newsletter",
    "stormcast",
]

# Score → level. Personal alerts fire at "high", or "elevated" for watchlist hits.
LEVELS = [(80, "critical"), (60, "high"), (40, "elevated"), (0, "info")]
LEVEL_RANK = {"info": 0, "elevated": 1, "high": 2, "critical": 3}
PERSONAL_ALERT_LEVEL = "high"
PERSONAL_WATCH_ALERT_LEVEL = "elevated"
PUBLIC_LEVEL = "elevated"  # shown on the dashboard and in the public feed
PUBLIC_PUSH_LEVEL = "critical"


@dataclass(frozen=True)
class Runtime:
    """Settings that come from the environment (Secret Manager in production)."""

    ntfy_server: str
    ntfy_topic: str | None  # personal topic; the name itself is the credential
    ntfy_public_topic: str | None  # disabled unless explicitly configured
    dashboard_url: str
    store: str  # "firestore" or a local directory path
    gcp_project: str | None
    send_alerts: bool

    @classmethod
    def from_env(cls) -> Runtime:
        return cls(
            ntfy_server=os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/"),
            ntfy_topic=os.environ.get("NTFY_TOPIC") or None,
            ntfy_public_topic=os.environ.get("NTFY_PUBLIC_TOPIC") or None,
            dashboard_url=os.environ.get("DASHBOARD_URL", "http://localhost:8080"),
            store=os.environ.get("RADAR_STORE", ".data"),
            gcp_project=os.environ.get("GOOGLE_CLOUD_PROJECT") or None,
            send_alerts=os.environ.get("SEND_ALERTS", "false").lower() == "true",
        )
