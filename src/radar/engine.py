"""Clustering and scoring: turn a stream of items into ranked incidents.

Design goal: every score is explainable. Each incident carries a breakdown of
exactly which signals contributed how many points.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from . import config
from .models import Incident, Item
from .text import contains_any, short_hash, tokens

MAX_ITEMS_PER_INCIDENT = 25
NEWS_KINDS = {"news"}
ADVISORY_KINDS = {"vendor", "gov"}


# ── Clustering ────────────────────────────────────────────────────────────────
def _similar(a: set[str], b: set[str]) -> bool:
    """Overlap coefficient on significant title words."""
    shared = a & b
    if len(shared) < 3:
        return False
    return len(shared) / min(len(a), len(b)) >= 0.5


HEADLINE_KINDS = NEWS_KINDS | ADVISORY_KINDS


def _incident_tokens(inc: Incident) -> list[set[str]]:
    """Word sets for each headline, compared one-to-one (never pooled: pooling
    many headlines makes accidental overlaps likely). Only human-written
    headlines take part; NVD/GitHub descriptions join by CVE only."""
    return [tokens(i.title) for i in inc.items if i.kind in HEADLINE_KINDS and len(i.cves) < ROUNDUP_CVE_COUNT][:10]


def _match_any(a: set[str], heads: list[set[str]], rare: set[str]) -> bool:
    return any(_match(a, h, rare) for h in heads)


ROUNDUP_CVE_COUNT = 4  # an item citing this many CVEs is a digest, not one event


def _rare_tokens(items: list[Item], incidents: list[Incident]) -> set[str]:
    """Words that appear in few titles right now, like "nginx2root" or "moveit".
    Sharing one is a strong hint that two headlines describe the same event."""
    titles = [i.title for i in items if i.kind in HEADLINE_KINDS] + [
        i.title for inc in incidents for i in inc.items[:10] if i.kind in HEADLINE_KINDS
    ]
    df: dict[str, int] = {}
    for t in titles:
        for w in tokens(t):
            df[w] = df.get(w, 0) + 1
    limit = max(3, int(0.03 * len(titles)))
    return {w for w, n in df.items() if n <= limit}


def _coined(w: str) -> bool:
    """Vulnerability nicknames mix letters and digits: log4shell, nginx2root."""
    return len(w) >= 6 and any(c.isdigit() for c in w) and any(c.isalpha() for c in w) and "." not in w


def _match(a: set[str], b: set[str], rare: set[str]) -> bool:
    shared = a & b
    rare_shared = shared & rare
    return _similar(a, b) or (len(rare_shared) >= 1 and len(shared) >= 2) or any(_coined(w) for w in rare_shared)


def cluster(items: list[Item], incidents: list[Incident], now: datetime) -> list[Incident]:
    """Attach each new item to an existing incident, or start a new one.

    Two items are the same event if they share a CVE, or (within 72h) if their
    titles share enough significant words, or a rare word plus one more:
    e.g. five outlets covering the same breach that has no CVE at all.
    """
    by_cve: dict[str, Incident] = {c: inc for inc in incidents for c in inc.cves}
    tok_cache = {inc.id: _incident_tokens(inc) for inc in incidents}
    rare = _rare_tokens(items, incidents)

    for item in sorted(items, key=lambda i: i.published):
        # Digests ("CISA adds four KEVs", "Patch Tuesday") stand alone: they must
        # not lend their CVEs, EPSS, or wording to the individual incidents.
        roundup = len(item.cves) >= ROUNDUP_CVE_COUNT
        matches = [] if roundup else [by_cve[c] for c in item.cves if c in by_cve]
        target = matches[0] if matches else None
        if target is None and item.kind in HEADLINE_KINDS and not roundup:
            it = tokens(item.title)
            recent = [inc for inc in incidents if item.published - inc.last_seen < timedelta(hours=72)]
            target = next((inc for inc in recent if _match_any(it, tok_cache[inc.id], rare)), None)

        # One focused item linking several incidents (shared CVEs) merges them.
        if target is not None and not roundup:
            for other in {id(m): m for m in matches[1:]}.values():
                if other is not target and other in incidents:
                    for i in other.items:
                        if len(target.items) < MAX_ITEMS_PER_INCIDENT and all(i.uid != t.uid for t in target.items):
                            target.items.append(i)
                    target.first_seen = min(target.first_seen, other.first_seen)
                    target.last_seen = max(target.last_seen, other.last_seen)
                    incidents.remove(other)
                    for c in other.cves:
                        by_cve[c] = target

        if target is None:
            target = Incident(
                id=short_hash(item.uid),
                title=item.title,
                first_seen=item.published,
                last_seen=item.published,
            )
            incidents.append(target)
            tok_cache[target.id] = []

        if all(i.uid != item.uid for i in target.items) and len(target.items) < MAX_ITEMS_PER_INCIDENT:
            target.items.append(item)
        target.first_seen = min(target.first_seen, item.published)
        target.last_seen = max(target.last_seen, item.published)
        target.title = _best_title(target)
        if not roundup:
            for c in item.cves:
                by_cve.setdefault(c, target)
        tok_cache[target.id] = _incident_tokens(target)

    return _merge_similar(incidents, rare)


def _merge_similar(incidents: list[Incident], rare: set[str]) -> list[Incident]:
    """Second pass: merge clusters whose headlines match each other. Needed
    because the first pass is order-dependent (a story can start its own cluster
    before the main one has formed)."""
    merged = True
    while merged:
        merged = False
        toks = {inc.id: _incident_tokens(inc) for inc in incidents}
        for a in incidents:
            for b in incidents:
                if a is b or not toks[a.id] or not toks[b.id]:
                    continue
                if abs(a.last_seen - b.last_seen) > timedelta(hours=72):
                    continue
                if any(_match_any(h, toks[b.id], rare) for h in toks[a.id]):
                    keep, drop = (a, b) if len(a.items) >= len(b.items) else (b, a)
                    for i in drop.items:
                        if len(keep.items) < MAX_ITEMS_PER_INCIDENT and all(i.uid != k.uid for k in keep.items):
                            keep.items.append(i)
                    keep.first_seen = min(keep.first_seen, drop.first_seen)
                    keep.last_seen = max(keep.last_seen, drop.last_seen)
                    keep.title = _best_title(keep)
                    incidents.remove(drop)
                    merged = True
                    break
            if merged:
                break
    return incidents


def _best_title(inc: Incident) -> str:
    """Prefer a news headline (human-friendly) over a raw CVE description."""
    for kind in ("news", "gov", "vendor", "kev", "ghsa", "nvd"):
        for i in inc.items:
            if i.kind == kind:
                return i.title
    return inc.title


# ── Scoring ───────────────────────────────────────────────────────────────────
def level_for(score: int) -> str:
    return next(name for floor, name in config.LEVELS if score >= floor)


def watch_hits(inc: Incident) -> list[str]:
    text = " ".join(f"{i.title} {i.summary}" for i in inc.items)
    return sorted({cat for cat, terms in config.WATCHLIST.items() if contains_any(text, terms)})


def score(inc: Incident, now: datetime) -> Incident:
    b: list[tuple[str, int]] = []
    items = inc.items
    text = " ".join(f"{i.title} {i.summary}" for i in items)

    if any(i.kev for i in items):
        b.append(("Confirmed exploited in the wild (CISA KEV)", 35))
    if any(i.ransomware for i in items):
        b.append(("Known use in ransomware campaigns", 10))

    cvss = max((i.cvss for i in items if i.cvss is not None), default=None)
    if cvss is not None and cvss >= 9.0:
        b.append((f"Critical severity (CVSS {cvss:.1f})", 20))
    elif cvss is not None and cvss >= 7.0:
        b.append((f"High severity (CVSS {cvss:.1f})", 8))

    epss = max((i.epss for i in items if i.epss is not None), default=None)
    if epss is not None and epss >= 0.5:
        b.append((f"High exploitation probability (EPSS {epss:.0%})", 20))
    elif epss is not None and epss >= 0.1:
        b.append((f"Elevated exploitation probability (EPSS {epss:.0%})", 8))

    outlets = {i.source for i in items if i.kind in NEWS_KINDS}
    if len(outlets) >= 2:
        b.append((f"Covered by {len(outlets)} news outlets", min(len(outlets), 5) * 8))
    recent_outlets = {i.source for i in items if i.kind in NEWS_KINDS and now - i.published < timedelta(hours=24)}
    if len(recent_outlets) >= 4:
        b.append(("Trending: 4+ outlets in the last 24 hours", 10))
    if any(i.kind in ADVISORY_KINDS for i in items):
        b.append(("Official vendor or government advisory", 10))

    if hits := contains_any(text, config.EXPLOITATION_TERMS, negatable=True):
        b.append((f"Exploitation language: “{hits[0]}”", 15))
    if hits := contains_any(text, config.IMPACT_TERMS):
        b.append((f"High-impact language: {', '.join(f'“{h}”' for h in hits[:2])}", min(len(hits), 2) * 8))
    if hits := contains_any(text, config.SCALE_TERMS):
        b.append((f"Large-scale language: “{hits[0]}”", 8))
    if contains_any(text, config.POC_TERMS):
        b.append(("Public proof-of-concept mentioned", 5))

    inc.watch = watch_hits(inc)
    if inc.watch:
        b.append((f"On your watchlist: {', '.join(inc.watch)}", 10))

    total = sum(p for _, p in b)
    # A CVSS score alone isn't corroboration: NVD publishes dozens of 9+ CVEs a day.
    corroborated = (
        any(i.kev for i in items) or len({i.source for i in items}) >= 2 or any(i.kind in ADVISORY_KINDS for i in items)
    )
    if not corroborated and total > 35:
        b.append(("Single source, awaiting corroboration (capped)", 35 - total))
        total = 35

    inc.breakdown = b
    inc.score = min(total, 100)
    inc.level = level_for(inc.score)
    return inc


def prune(incidents: list[Incident], now: datetime) -> list[Incident]:
    """Drop stale incidents. Low-signal singletons expire fast to keep state small."""
    keep = []
    for inc in incidents:
        age = now - inc.last_seen
        if age > timedelta(days=config.INCIDENT_WINDOW_DAYS):
            continue
        if inc.level == "info" and len(inc.items) == 1 and age > timedelta(hours=48):
            continue
        keep.append(inc)
    keep.sort(key=lambda i: (i.score, i.last_seen), reverse=True)
    return keep[:400]


# ── Alert decisions ───────────────────────────────────────────────────────────
def should_alert(inc: Incident, already: str | None, *, personal: bool) -> bool:
    """Alert once per level: re-alert only when an incident escalates."""
    rank = config.LEVEL_RANK
    if personal:
        floor = config.PERSONAL_WATCH_ALERT_LEVEL if inc.watch else config.PERSONAL_ALERT_LEVEL
    else:
        floor = config.PUBLIC_PUSH_LEVEL
    if rank[inc.level] < rank[floor]:
        return False
    return already is None or rank[inc.level] > rank[already]
