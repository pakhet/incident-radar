from datetime import UTC, datetime

from starlette.testclient import TestClient

from radar import config, feeds, notify, sources, text
from radar.models import Incident, Item

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)

EVIL_RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>t</title>
<item><title>&lt;script&gt;alert(1)&lt;/script&gt;Big breach CVE-2026-1234</title>
<link>javascript:alert(1)</link><pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Real story about CVE-2026-5555</title><link>https://news.example/a</link>
<description>&lt;img src=x onerror=alert(1)&gt;Details</description>
<pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Week in review: lots of things</title><link>https://news.example/b</link>
<pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_feed_parser_drops_unsafe_links_strips_html_and_skips_digests():
    items = sources.parse_feed(config.Feed("Evil", "https://x", "news"), EVIL_RSS, NOW)
    assert len(items) == 1  # javascript: link dropped, digest skipped
    [it] = items
    assert it.url == "https://news.example/a"
    assert "<" not in it.summary and "onerror" not in it.summary
    assert it.cves == ["CVE-2026-5555"]


def test_kev_parser_respects_lookback():
    data = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1",
                "dateAdded": "2026-11-18",
                "vulnerabilityName": "Acme RCE",
                "knownRansomwareCampaignUse": "Known",
            },
            {"cveID": "CVE-2020-1", "dateAdded": "2020-01-01", "vulnerabilityName": "Old"},
        ]
    }
    [it] = sources.parse_kev(data, NOW)
    assert it.kev and it.ransomware and it.cves == ["CVE-2026-1"]


def test_nvd_parser_keeps_only_critical():
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1",
                    "published": "2026-11-18T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "bad"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-2",
                    "published": "2026-11-18T00:00:00.000",
                    "descriptions": [],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                }
            },
        ]
    }
    assert [i.cves for i in sources.parse_nvd(data)] == [["CVE-2026-1"]]


def test_negation_and_questions():
    assert text.contains_any("actively exploited now", ["actively exploited"], negatable=True)
    assert not text.contains_any("not actively exploited", ["actively exploited"], negatable=True)
    assert not text.contains_any("is it actively exploited? maybe", ["actively exploited"], negatable=True)
    assert not text.contains_any("open source software", ["rce"])  # word boundaries


def _incident(title='<b>Evil</b> & "quoted" title'):
    it = Item(uid="a", source="A", kind="news", title=title, url="javascript:alert(1)", published=NOW)
    return Incident(
        id="abc",
        title=title,
        first_seen=NOW,
        last_seen=NOW,
        items=[it],
        score=90,
        level="critical",
        breakdown=[("Test", 90)],
    )


def test_atom_feed_escapes_untrusted_text():
    inc = _incident()
    pub = {"generated": "2026-11-19T12:00:00Z", "incidents": [{**inc.to_dict(), "cves": [], "sources": ["A"]}]}
    xml = feeds.atom(pub, "https://radar.example").decode()
    assert "<b>Evil" not in xml and "&lt;b&gt;Evil" in xml


def test_ntfy_message_is_clean_and_links_are_safe():
    msg = notify.build_message(_incident("Evil\r\nX-Injected: yes"), "https://radar.example")
    assert "\n" not in msg["title"] and "\r" not in msg["title"]
    assert msg["click"] == ""  # javascript: link refused
    assert msg["priority"] == 5


def test_api_sets_security_headers_and_rejects_writes(tmp_path, monkeypatch):
    from radar import api

    monkeypatch.setattr(api, "_store", None)
    monkeypatch.setattr(api, "rt", config.Runtime.from_env().__class__(**{**api.rt.__dict__, "store": str(tmp_path)}))
    api._cache.update(at=0.0, data=None)
    c = TestClient(api.app)
    r = c.get("/api/incidents")
    assert r.status_code == 200 and r.json()["incidents"] == []
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert c.post("/api/incidents").status_code == 405
    assert c.get("/feed.xml").headers["content-type"].startswith("application/atom+xml")


def test_clean_urls_serve_html_pages(tmp_path, monkeypatch):
    import importlib

    (tmp_path / "index.html").write_text("home")
    (tmp_path / "how-it-works.html").write_text("method")
    monkeypatch.setenv("WEB_DIR", str(tmp_path))
    from radar import api

    api = importlib.reload(api)
    c = TestClient(api.app)
    assert c.get("/").text == "home"
    assert c.get("/how-it-works").text == "method"
    assert c.get("/nope").status_code == 404
