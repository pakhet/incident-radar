"""State storage. Firestore in production, JSON files locally.

The whole working state fits in a few documents, so each collector run costs a
handful of reads and writes, comfortably inside Firestore's free tier.

  radar/state   incidents, alert history, source health, HTTP cache validators
  radar/seen    item UIDs already processed (with timestamps, pruned)
  radar/public  the dashboard's read model: only public-level incidents
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

DOCS = ("state", "seen", "public")


class Store(Protocol):
    def load(self, name: str) -> dict[str, Any]: ...
    def save(self, name: str, data: dict[str, Any]) -> None: ...


class FileStore:
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def load(self, name: str) -> dict[str, Any]:
        p = self.root / f"{name}.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def save(self, name: str, data: dict[str, Any]) -> None:
        tmp = self.root / f".{name}.json.tmp"
        tmp.write_text(json.dumps(data, indent=1))
        tmp.replace(self.root / f"{name}.json")  # atomic on POSIX


class FirestoreStore:
    def __init__(self, project: str | None):
        from google.cloud import firestore  # imported lazily: not needed locally

        self.col = firestore.Client(project=project).collection("radar")

    def load(self, name: str) -> dict[str, Any]:
        snap = self.col.document(name).get()
        # Stored as a JSON string: keeps nested lists simple and the size predictable.
        return json.loads(snap.get("json")) if snap.exists else {}

    def save(self, name: str, data: dict[str, Any]) -> None:
        self.col.document(name).set({"json": json.dumps(data, separators=(",", ":"))})


def open_store(spec: str, project: str | None) -> Store:
    return FirestoreStore(project) if spec == "firestore" else FileStore(spec)
