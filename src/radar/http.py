"""A small, defensive HTTP client for fetching untrusted third-party data."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from . import config


class FetchError(Exception):
    pass


@dataclass
class Response:
    status: int
    body: bytes
    etag: str | None
    last_modified: str | None


class Http:
    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(
            timeout=config.HTTP_TIMEOUT_S,
            follow_redirects=True,
            max_redirects=3,
            headers={"User-Agent": config.USER_AGENT},
        )

    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> Response:
        """GET with a size cap, HTTPS-only, and conditional-request support."""
        if not url.startswith("https://"):
            raise FetchError(f"refusing non-HTTPS URL: {url}")
        h = dict(headers or {})
        if etag:
            h["If-None-Match"] = etag
        if last_modified:
            h["If-Modified-Since"] = last_modified
        try:
            with self.client.stream("GET", url, params=params, headers=h) as r:
                if not str(r.url).startswith("https://"):
                    raise FetchError(f"redirected off HTTPS: {r.url}")
                if r.status_code == 304:
                    return Response(304, b"", etag, last_modified)
                if r.status_code >= 400:
                    raise FetchError(f"HTTP {r.status_code} from {url}")
                chunks, size = [], 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > config.MAX_RESPONSE_BYTES:
                        raise FetchError(f"response from {url} exceeded {config.MAX_RESPONSE_BYTES} bytes")
                    chunks.append(chunk)
                return Response(
                    r.status_code,
                    b"".join(chunks),
                    r.headers.get("etag"),
                    r.headers.get("last-modified"),
                )
        except httpx.HTTPError as e:
            raise FetchError(f"{type(e).__name__} fetching {url}") from e
