from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

Kind = Literal["kev", "nvd", "ghsa", "news", "vendor", "gov"]


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)


@dataclass
class Item:
    """One observation from one source (an article, an advisory, a KEV entry)."""

    uid: str  # stable, e.g. "kev:CVE-2021-44228" or "news:bleepingcomputer:<hash>"
    source: str  # human-readable source name
    kind: Kind
    title: str
    url: str
    published: datetime
    summary: str = ""
    cves: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    ransomware: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["published"] = iso(self.published)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Item:
        return cls(**{**d, "published": parse_iso(d["published"])})


@dataclass
class Incident:
    """A cluster of items that describe the same event."""

    id: str
    title: str
    first_seen: datetime
    last_seen: datetime
    items: list[Item] = field(default_factory=list)
    score: int = 0
    level: str = "info"
    breakdown: list[tuple[str, int]] = field(default_factory=list)
    watch: list[str] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return sorted({c for i in self.items for c in i.cves})

    @property
    def sources(self) -> list[str]:
        return sorted({i.source for i in self.items})

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "items": [i.to_dict() for i in self.items],
            "score": self.score,
            "level": self.level,
            "breakdown": [list(b) for b in self.breakdown],
            "watch": self.watch,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Incident:
        return cls(
            id=d["id"],
            title=d["title"],
            first_seen=parse_iso(d["first_seen"]),
            last_seen=parse_iso(d["last_seen"]),
            items=[Item.from_dict(i) for i in d["items"]],
            score=d.get("score", 0),
            level=d.get("level", "info"),
            breakdown=[(r, p) for r, p in d.get("breakdown", [])],
            watch=d.get("watch", []),
        )
