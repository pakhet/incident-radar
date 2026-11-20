"""Push alerts via ntfy (https://ntfy.sh)."""

from __future__ import annotations

import httpx

from . import config
from .models import Incident
from .text import clean, safe_url

PRIORITY = {"critical": 5, "high": 4, "elevated": 3, "info": 2}
TAGS = {"critical": ["rotating_light"], "high": ["warning"], "elevated": ["eyes"], "info": []}


def build_message(inc: Incident, dashboard_url: str) -> dict:
    """JSON publish body. Using JSON (not headers) avoids header-injection from
    attacker-controlled headlines; all text is cleaned and length-limited."""
    lines = [f"Score {inc.score}/100 · {len(inc.sources)} source(s)"]
    if inc.cves:
        lines.append("CVEs: " + ", ".join(inc.cves[:5]) + (" …" if len(inc.cves) > 5 else ""))
    lines += [f"• {reason}" for reason, _ in inc.breakdown[:4]]
    link = next((safe_url(i.url) for i in inc.items if i.kind == "news"), "") or safe_url(inc.items[0].url)
    return {
        "title": clean(f"[{inc.level.upper()}] {inc.title}", 250),
        "message": "\n".join(clean(line, 200) for line in lines)[:1000],
        "priority": PRIORITY[inc.level],
        "tags": TAGS[inc.level],
        "click": link,
        "actions": [{"action": "view", "label": "Dashboard", "url": f"{dashboard_url}/#i-{inc.id}"}],
    }


def send(server: str, topic: str, inc: Incident, dashboard_url: str, client: httpx.Client | None = None) -> None:
    body = {"topic": topic, **build_message(inc, dashboard_url)}
    c = client or httpx.Client(timeout=15, headers={"User-Agent": config.USER_AGENT})
    r = c.post(server, json=body)
    r.raise_for_status()
