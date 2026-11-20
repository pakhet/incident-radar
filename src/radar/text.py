"""Text helpers. All third-party text is treated as untrusted."""

from __future__ import annotations

import hashlib
import html
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{2,}")

STOPWORDS = set(
    """the and for with from that this into over after about their them they have has had
    are was were will its new not but can could may might more than when what which who
    how why all any our your you out now just also via amid says said report reports
    update updates patch patches patched fix fixes fixed flaw flaws bug bugs vulnerability
    vulnerabilities security attack attacks attackers hackers critical high severity issue
    issues warn warns warning users week weekly today year million""".split()
)


def clean(s: str | None, limit: int = 500) -> str:
    """Strip HTML and control characters, collapse whitespace, truncate."""
    if not s:
        return ""
    s = html.unescape(_TAG_RE.sub(" ", s))
    s = _WS_RE.sub(" ", _CTRL_RE.sub("", s)).strip()
    return s[: limit - 1] + "…" if len(s) > limit else s


def find_cves(*texts: str) -> list[str]:
    return sorted({m.upper() for t in texts if t for m in CVE_RE.findall(t)})


def tokens(s: str) -> set[str]:
    """Significant lowercase words, used to cluster articles about the same event."""
    return {w.strip(".-") for w in _WORD_RE.findall(s.lower()) if w not in STOPWORDS and not w.startswith("cve-")}


def short_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def safe_url(u: str | None) -> str:
    """Only http(s) links are ever stored or rendered (blocks javascript: etc.)."""
    if u and (u.startswith("https://") or u.startswith("http://")):
        return u[:2000]
    return ""


_NEGATION_RE = re.compile(r"\b(no|not|never|without|unconfirmed|no evidence|no signs?|no indication)\b[^.;]{0,40}$")


def contains_any(haystack: str, needles: list[str], *, negatable: bool = False) -> list[str]:
    """Word-boundary matches (so "rce" doesn't hit "source").

    With negatable=True, a match preceded closely by a negation ("no evidence
    it has been exploited in the wild") doesn't count.
    """
    h = f" {haystack.lower()} "
    hits = []
    for n in needles:
        for m in re.finditer(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", h):
            if negatable:
                if _NEGATION_RE.search(h[max(0, m.start() - 60) : m.start()]):
                    continue
                # "Is X under active exploitation?" is a question, not a claim
                end = re.search(r"[.?!]", h[m.end() :])
                if end and end.group() == "?":
                    continue
            hits.append(n)
            break
    return hits
