"""Collectors. Each returns a list of Items; each may raise FetchError."""

from __future__ import annotations

import json
from calendar import timegm
from datetime import UTC, datetime, timedelta

import feedparser

from . import config
from .http import FetchError, Http
from .models import Item, utcnow
from .text import clean, contains_any, find_cves, safe_url, short_hash


def _date(s: str) -> datetime:
    # KEV uses YYYY-MM-DD; NVD/GitHub use ISO 8601
    if len(s) == 10:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=UTC)
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)


# ── CISA Known Exploited Vulnerabilities ──────────────────────────────────────
def parse_kev(data: dict, now: datetime) -> list[Item]:
    cutoff = now - timedelta(days=config.KEV_LOOKBACK_DAYS)
    out = []
    for v in data.get("vulnerabilities", []):
        added = _date(v["dateAdded"])
        if added < cutoff:
            continue
        cve = v["cveID"].upper()
        out.append(
            Item(
                uid=f"kev:{cve}",
                source="CISA KEV",
                kind="kev",
                # vulnerabilityName already names the vendor and product
                title=clean(v.get("vulnerabilityName") or f"{v.get('vendorProject', '')} {v.get('product', '')}", 200),
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=added,
                summary=clean(v.get("shortDescription")),
                cves=[cve],
                kev=True,
                ransomware=v.get("knownRansomwareCampaignUse", "").lower() == "known",
            )
        )
    return out


def fetch_kev(http: Http, now: datetime) -> list[Item]:
    r = http.get(config.KEV_URL)
    return parse_kev(json.loads(r.body), now)


# ── NVD: newly published critical CVEs ────────────────────────────────────────
def _nvd_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def parse_nvd(data: dict) -> list[Item]:
    out = []
    for wrapper in data.get("vulnerabilities", []):
        c = wrapper.get("cve", {})
        cvss = _nvd_cvss(c.get("metrics", {}))
        if cvss is None or cvss < 9.0:
            continue
        cve = c["id"].upper()
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append(
            Item(
                uid=f"nvd:{cve}",
                source="NVD",
                kind="nvd",
                title=clean(f"{cve}: {desc}", 160),
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=_date(c["published"]),
                summary=clean(desc),
                cves=[cve],
                cvss=cvss,
                kev=bool(c.get("cisaExploitAdd")),
            )
        )
    return out


def fetch_nvd(http: Http, now: datetime) -> list[Item]:
    start = now - timedelta(hours=config.NVD_LOOKBACK_HOURS)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    params = {"pubStartDate": start.strftime(fmt), "pubEndDate": now.strftime(fmt), "resultsPerPage": 2000}
    r = http.get(config.NVD_URL, params=params)
    return parse_nvd(json.loads(r.body))


# ── GitHub reviewed advisories (open source ecosystems) ───────────────────────
def parse_ghsa(data: list) -> list[Item]:
    out = []
    for a in data:
        cvss = (a.get("cvss_severities", {}).get("cvss_v4") or {}).get("score") or (a.get("cvss") or {}).get("score")
        pkgs = sorted({(v.get("package") or {}).get("name", "") for v in a.get("vulnerabilities", [])} - {""})
        cves = [a["cve_id"].upper()] if a.get("cve_id") else []
        title = clean(a.get("summary"), 160)
        if pkgs:
            title = clean(f"{', '.join(pkgs[:3])}: {title}", 200)
        raw_epss = a.get("epss")
        if isinstance(raw_epss, list):  # API shape has varied; accept list or object
            raw_epss = raw_epss[0] if raw_epss else None
        epss = raw_epss.get("percentage") if isinstance(raw_epss, dict) else None
        out.append(
            Item(
                uid=f"ghsa:{a['ghsa_id']}",
                source="GitHub Advisories",
                kind="ghsa",
                title=title,
                url=safe_url(a.get("html_url")),
                published=_date(a["published_at"]),
                summary=clean(a.get("description")),
                cves=cves,
                cvss=float(cvss) if cvss else None,
                epss=float(epss) if epss is not None else None,
            )
        )
    return out


def fetch_ghsa(http: Http, now: datetime) -> list[Item]:
    params = {"type": "reviewed", "severity": "critical", "per_page": 50, "sort": "published", "direction": "desc"}
    r = http.get(config.GHSA_URL, params=params, headers={"Accept": "application/vnd.github+json"})
    return parse_ghsa(json.loads(r.body))


# ── RSS / Atom feeds ──────────────────────────────────────────────────────────
def parse_feed(feed: config.Feed, body: bytes, now: datetime) -> list[Item]:
    parsed = feedparser.parse(body)
    cutoff = now - timedelta(days=config.NEWS_MAX_AGE_DAYS)
    out = []
    for e in parsed.entries:
        t = e.get("published_parsed") or e.get("updated_parsed")
        published = datetime.fromtimestamp(timegm(t), UTC) if t else now
        if published < cutoff:
            continue
        url = safe_url(e.get("link"))
        title = clean(e.get("title"), 200)
        if not title or not url or contains_any(title, config.SKIP_TITLE_TERMS):
            continue
        summary = clean(e.get("summary"))
        out.append(
            Item(
                uid=f"{feed.kind}:{short_hash(url)}",
                source=feed.name,
                kind=feed.kind,  # type: ignore[arg-type]
                title=title,
                url=url,
                published=min(published, now),
                summary=summary,
                cves=find_cves(title, summary),
            )
        )
    return out


# ── EPSS enrichment (probability a CVE is exploited in the next 30 days) ──────
def fetch_epss(http: Http, cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 100):
        batch = cves[i : i + 100]
        r = http.get(config.EPSS_URL, params={"cve": ",".join(batch)})
        for row in json.loads(r.body).get("data", []):
            scores[row["cve"].upper()] = float(row["epss"])
    return scores


__all__ = [
    "FetchError",
    "fetch_epss",
    "fetch_ghsa",
    "fetch_kev",
    "fetch_nvd",
    "parse_feed",
    "parse_ghsa",
    "parse_kev",
    "parse_nvd",
    "utcnow",
]
