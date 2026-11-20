"""End-to-end collector runs against fake sources (no network)."""

import json
from dataclasses import replace

from radar import collector, config
from radar.http import FetchError, Response
from radar.store import FileStore


class FakeHttp:
    def __init__(self, kev):
        self.kev = kev

    def get(self, url, **kw):
        if url == config.KEV_URL:
            return Response(200, json.dumps(self.kev).encode(), None, None)
        if url == config.EPSS_URL:
            return Response(200, b'{"data": []}', None, None)
        raise FetchError("offline")  # every other source "fails"


def kev(*cves):
    return {
        "vulnerabilities": [
            {
                "cveID": c,
                "dateAdded": "2026-11-19",
                "vulnerabilityName": f"Acme VPN {c}",
                "knownRansomwareCampaignUse": "Known",
            }
            for c in cves
        ]
    }


def test_bootstrap_is_silent_then_new_events_alert(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(collector.notify, "send", lambda *a, **k: sent.append(a[2].id))
    monkeypatch.setattr(
        collector,
        "utcnow",
        lambda: __import__("datetime").datetime(2026, 11, 19, 12, tzinfo=__import__("datetime").UTC),
    )
    rt = replace(config.Runtime.from_env(), store=str(tmp_path), ntfy_topic="t", send_alerts=True)
    store = FileStore(str(tmp_path))

    s1 = collector.run_once(store, FakeHttp(kev("CVE-2026-1")), rt)
    assert s1["bootstrap"] and s1["alerts"] == 0 and sent == []
    assert "NVD" in s1["sources_failed"]  # failures are reported, not fatal

    s2 = collector.run_once(store, FakeHttp(kev("CVE-2026-1", "CVE-2026-2")), rt)
    assert not s2["bootstrap"] and len(sent) == 1  # only the new one

    s3 = collector.run_once(store, FakeHttp(kev("CVE-2026-1", "CVE-2026-2")), rt)
    assert s3["alerts"] == 1 - 1 and len(sent) == 1  # no repeats

    public = store.load("public")
    assert {i["cves"][0] for i in public["incidents"]} == {"CVE-2026-1", "CVE-2026-2"}
    assert public["health"]["CISA KEV"]["ok"] is True
