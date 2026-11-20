from datetime import UTC, datetime, timedelta

from radar import engine
from radar.models import Item

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)


def item(uid, title, kind="news", source=None, cves=(), hours_ago=1, **kw):
    return Item(
        uid=uid,
        source=source or uid.split(":")[0],
        kind=kind,
        title=title,
        url=f"https://example.com/{uid}",
        published=NOW - timedelta(hours=hours_ago),
        cves=list(cves),
        **kw,
    )


def run(items):
    incs = engine.cluster(items, [], NOW)
    for i in incs:
        engine.score(i, NOW)
    return sorted(incs, key=lambda i: -i.score)


def test_shared_cve_clusters_across_source_types():
    incs = run(
        [
            item("kev:1", "Acme Gateway RCE", kind="kev", source="CISA KEV", cves=["CVE-2026-0001"], kev=True),
            item(
                "bc:1", "Hackers exploit Acme Gateway CVE-2026-0001", source="BleepingComputer", cves=["CVE-2026-0001"]
            ),
        ]
    )
    assert len(incs) == 1 and len(incs[0].items) == 2


def test_coined_vulnerability_name_clusters_headlines_without_cves():
    incs = run(
        [
            item("a:1", "Critical NGINX 'NGINX2Root' bugs let attackers hijack servers", source="A"),
            item("b:1", "F5 Patches Critical NGINX2Root Flaws as PoC Exploits Go Public", source="B"),
            item("c:1", "Unrelated phishing campaign targets accountants", source="C"),
        ]
    )
    sizes = sorted(len(i.items) for i in incs)
    assert sizes == [1, 2]


def test_unrelated_headlines_do_not_chain_together():
    incs = run(
        [
            item("a:1", "Critical Puppet RCE flaw exploited against enterprise servers", source="A"),
            item("b:1", "Critical VMware vCenter flaw lets attackers bypass authentication", source="B"),
            item("c:1", "Ten-year-old NGINX HTTP/2 flaw lets attackers execute code", source="C"),
        ]
    )
    assert len(incs) == 3


def test_roundup_does_not_lend_cves_to_other_incidents():
    incs = run(
        [
            item("kev:1", "Puppet RCE", kind="kev", source="CISA KEV", cves=["CVE-2026-1111"], kev=True),
            item(
                "gov:1",
                "CISA adds four known exploited vulnerabilities to catalog",
                kind="gov",
                source="CISA",
                cves=["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333", "CVE-2026-4444"],
            ),
        ]
    )
    puppet = next(i for i in incs if any(x.kev for x in i.items))
    assert puppet.cves == ["CVE-2026-1111"]


def test_single_uncorroborated_article_is_capped():
    [inc] = run(
        [item("a:1", "Zero-day ransomware worm hits millions in massive supply chain attack on nginx", source="A")]
    )
    assert inc.score == 35
    assert inc.level == "info"
    assert any("corroboration" in r for r, _ in inc.breakdown)


def test_negated_exploitation_language_is_ignored():
    [inc] = run(
        [
            item(
                "a:1",
                "Critical nginx flaw patched",
                source="A",
                summary="There is no evidence it has been exploited in the wild.",
            ),
        ]
    )
    assert not any(r.startswith("Exploitation language") for r, _ in inc.breakdown)


def test_kev_with_coverage_scores_high_and_explains_itself():
    [inc] = run(
        [
            item(
                "kev:1", "Acme VPN auth bypass", kind="kev", source="CISA KEV", cves=["CVE-2026-9"], kev=True, cvss=9.8
            ),
            item("a:1", "Acme VPN zero-day actively exploited CVE-2026-9", source="A", cves=["CVE-2026-9"]),
            item("b:1", "Attackers exploit Acme VPN CVE-2026-9", source="B", cves=["CVE-2026-9"]),
        ]
    )
    assert inc.level == "critical"
    assert sum(p for _, p in inc.breakdown) >= inc.score  # breakdown accounts for every point (score capped at 100)
    assert "Edge & VPN" in inc.watch


def test_alerts_fire_once_per_level_and_on_escalation():
    [inc] = run([item("kev:1", "x", kind="kev", source="CISA KEV", cves=["CVE-1"], kev=True, cvss=9.8)])
    inc.level, inc.watch = "high", []
    assert engine.should_alert(inc, None, personal=True)
    assert not engine.should_alert(inc, "high", personal=True)
    inc.level = "critical"
    assert engine.should_alert(inc, "high", personal=True)


def test_watchlist_lowers_personal_threshold_only():
    [inc] = run([item("kev:1", "x", kind="kev", source="CISA KEV", cves=["CVE-1"], kev=True)])
    inc.level = "elevated"
    inc.watch = []
    assert not engine.should_alert(inc, None, personal=True)
    inc.watch = ["Web & proxies"]
    assert engine.should_alert(inc, None, personal=True)
    assert not engine.should_alert(inc, None, personal=False)  # public push needs critical


def test_prune_drops_stale_noise_but_keeps_signal():
    old_noise = item("n:1", "minor thing", hours_ago=60)
    signal = item("kev:1", "big thing", kind="kev", source="CISA KEV", cves=["CVE-2"], kev=True, cvss=9.9, hours_ago=60)
    incs = run([old_noise, signal])
    kept = engine.prune(incs, NOW)
    assert [i.items[0].uid for i in kept] == ["kev:1"]
