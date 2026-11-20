"""The collector: one run = fetch → dedupe → enrich → cluster → score → alert → save.

Runs as a Cloud Run Job every 15 minutes (Cloud Scheduler). Locally:
    uv run python -m radar.collector
"""

from __future__ import annotations

import json
import sys
import time
from datetime import timedelta
from typing import Any

from . import config, engine, notify, sources
from .http import FetchError, Http
from .models import Incident, Item, iso, utcnow
from .store import Store, open_store


def log(event: str, **fields: Any) -> None:
    """Structured JSON logs; Cloud Logging parses `severity` and `message`."""
    print(json.dumps({"severity": fields.pop("severity", "INFO"), "message": event, **fields}), flush=True)


def collect(http: Http, state: dict, now) -> list[Item]:
    health: dict = state.setdefault("health", {})
    cache: dict = state.setdefault("cache", {})
    items: list[Item] = []

    def run(name: str, fn) -> None:
        t0 = time.monotonic()
        try:
            got = fn()
            items.extend(got)
            health[name] = {"ok": True, "at": iso(now), "items": len(got)}
        except Exception as e:  # one bad source must never break the run
            prev = health.get(name, {})
            health[name] = {"ok": False, "at": iso(now), "error": str(e)[:200], "last_ok": prev.get("last_ok")}
            log("source failed", severity="WARNING", source=name, error=str(e)[:200])
        else:
            health[name]["last_ok"] = iso(now)
        health[name]["ms"] = int((time.monotonic() - t0) * 1000)

    run("CISA KEV", lambda: sources.fetch_kev(http, now))
    run("NVD", lambda: sources.fetch_nvd(http, now))
    run("GitHub Advisories", lambda: sources.fetch_ghsa(http, now))

    for feed in config.FEEDS:

        def fetch_feed(feed=feed):
            v = cache.get(feed.url, {})
            r = http.get(feed.url, etag=v.get("etag"), last_modified=v.get("lm"))
            cache[feed.url] = {"etag": r.etag, "lm": r.last_modified}
            return [] if r.status == 304 else sources.parse_feed(feed, r.body, now)

        run(feed.name, fetch_feed)
    return items


def run_once(store: Store, http: Http, rt: config.Runtime) -> dict:
    now = utcnow()
    state = store.load("state")
    seen: dict[str, str] = store.load("seen")
    bootstrap = not state  # first run: build state, but don't flood alerts

    incidents = [Incident.from_dict(d) for d in state.get("incidents", [])]
    fetched = collect(http, state, now)
    new = [i for i in fetched if i.uid not in seen]
    for i in new:
        seen[i.uid] = iso(now)

    # EPSS for any CVE we don't have a score for yet
    known_epss = {c: i.epss for inc in incidents for i in inc.items for c in i.cves if i.epss is not None}
    want = sorted({c for i in new for c in i.cves if c not in known_epss})
    if want:
        try:
            known_epss.update(sources.fetch_epss(http, want))
        except FetchError as e:
            log("epss failed", severity="WARNING", error=str(e))
    for i in new:
        if i.epss is None and 0 < len(i.cves) < engine.ROUNDUP_CVE_COUNT:
            i.epss = max((known_epss[c] for c in i.cves if c in known_epss), default=None)

    incidents = engine.cluster(new, incidents, now)
    for inc in incidents:
        engine.score(inc, now)
    incidents = engine.prune(incidents, now)

    # Alerts
    alerted: dict[str, dict] = state.get("alerted", {})
    sent = 0
    for inc in incidents:
        prev = alerted.get(inc.id, {})
        for channel, topic, personal in (
            ("personal", rt.ntfy_topic, True),
            ("public", rt.ntfy_public_topic, False),
        ):
            if not engine.should_alert(inc, prev.get(channel), personal=personal):
                continue
            if topic and rt.send_alerts and not bootstrap:
                try:
                    notify.send(rt.ntfy_server, topic, inc, rt.dashboard_url)
                    sent += 1
                    log("alert sent", channel=channel, incident=inc.id, level=inc.level, score=inc.score)
                except Exception as e:
                    log("alert failed", severity="ERROR", channel=channel, error=str(e)[:200])
                    continue
            prev[channel] = inc.level  # recorded even when muted, so unmuting doesn't replay history
        if prev:
            alerted[inc.id] = prev

    live_ids = {i.id for i in incidents}
    state["alerted"] = {k: v for k, v in alerted.items() if k in live_ids}
    state["incidents"] = [i.to_dict() for i in incidents]
    state["last_run"] = iso(now)

    cutoff = iso(now - timedelta(days=10))
    seen = {k: v for k, v in seen.items() if v >= cutoff}

    rank = config.LEVEL_RANK
    public = [i for i in incidents if rank[i.level] >= rank[config.PUBLIC_LEVEL]]
    store.save("seen", seen)
    store.save("state", state)
    store.save(
        "public",
        {
            "generated": iso(now),
            "incidents": [_public_view(i) for i in public],
            "health": state.get("health", {}),
        },
    )
    summary = {
        "fetched": len(fetched),
        "new": len(new),
        "incidents": len(incidents),
        "public": len(public),
        "alerts": sent,
        "bootstrap": bootstrap,
        "sources_failed": sorted(k for k, v in state["health"].items() if not v["ok"]),
    }
    log("run complete", **summary)
    return summary


def _public_view(inc: Incident) -> dict:
    d = inc.to_dict()
    d["cves"] = inc.cves
    d["sources"] = inc.sources
    # Keep the public payload lean: just what the dashboard renders.
    d["items"] = [
        {k: i[k] for k in ("source", "kind", "title", "url", "published", "cvss", "epss", "kev")} for i in d["items"]
    ]
    return d


def main() -> int:
    rt = config.Runtime.from_env()
    store = open_store(rt.store, rt.gcp_project)
    try:
        run_once(store, Http(), rt)
    except Exception as e:
        log("run failed", severity="ERROR", error=repr(e)[:500])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
