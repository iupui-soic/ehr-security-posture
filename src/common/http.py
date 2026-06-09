"""Polite HTTP client: rate limiting, exponential backoff, auth headers.

A thin wrapper over ``requests`` that every acquire module shares so rate-limit
and retry behaviour is uniform and ToS-respecting. Source-specific factories
(``github_client``, ``nvd_client``, ...) preset the right base URL, auth header,
and a conservative minimum inter-request interval.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterator

import requests

from . import config
from .logging import get_logger

log = get_logger("http")


class RateLimiter:
    """Enforce a minimum interval between successive requests (per client)."""

    def __init__(self, min_interval_s: float):
        self.min_interval_s = min_interval_s
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval_s <= 0:
            return
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval_s:
            time.sleep(self.min_interval_s - delta)
        self._last = time.monotonic()


@dataclass
class Client:
    base_url: str = ""
    headers: dict | None = None
    rate: RateLimiter | None = None
    timeout: float = 60.0

    def __post_init__(self):
        snap_http = config.load_snapshot().http
        self.max_retries = int(snap_http.get("max_retries", 5))
        self.backoff_seconds = float(snap_http.get("backoff_seconds", 2.0))
        self.session = requests.Session()
        if self.headers:
            self.session.headers.update(self.headers)
        self.session.headers.setdefault(
            "User-Agent", "ehr-security-benchmark/1.0 (research; measurement-only)"
        )

    # -- core request with backoff -------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        full = url if url.startswith("http") else f"{self.base_url}{url}"
        kwargs.setdefault("timeout", self.timeout)
        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            if self.rate:
                self.rate.wait()
            try:
                resp = self.session.request(method, full, **kwargs)
            except requests.RequestException as exc:  # network-level
                last_exc = exc
                wait = self.backoff_seconds * (2 ** (attempt - 1))
                log.warning("%s %s failed (%s); retry %d/%d in %.1fs",
                            method, full, exc, attempt, self.max_retries, wait)
                time.sleep(wait)
                continue

            if resp.status_code in (429,) or 500 <= resp.status_code < 600:
                wait = self._retry_after(resp, attempt)
                log.warning("%s %s -> %d; retry %d/%d in %.1fs",
                            method, full, resp.status_code, attempt, self.max_retries, wait)
                time.sleep(wait)
                continue

            # GitHub secondary/abuse rate limit: 403 with remaining==0.
            if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
                wait = self._retry_after(resp, attempt)
                log.warning("rate limited (403) on %s; sleeping %.1fs", full, wait)
                time.sleep(wait)
                continue

            return resp

        if last_exc:
            raise last_exc
        raise RuntimeError(f"exhausted retries for {method} {full}")

    def _retry_after(self, resp: requests.Response, attempt: int) -> float:
        # Honour Retry-After / X-RateLimit-Reset when present, else exp backoff.
        ra = resp.headers.get("Retry-After")
        if ra:
            try:
                return float(ra)
            except ValueError:
                pass
        reset = resp.headers.get("X-RateLimit-Reset")
        if reset:
            try:
                delta = float(reset) - time.time()
                if delta > 0:
                    return min(delta + 1.0, 120.0)
            except ValueError:
                pass
        return self.backoff_seconds * (2 ** (attempt - 1))

    # -- convenience ----------------------------------------------------------
    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def get_json(self, url: str, **kwargs) -> Any:
        resp = self.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def post_json(self, url: str, json_body: Any, **kwargs) -> Any:
        resp = self.request("POST", url, json=json_body, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def paginate(self, url: str, params: dict | None = None,
                 max_pages: int = 100) -> Iterator[Any]:
        """Follow RFC-5988 Link rel=next pagination (GitHub/Gitea style)."""
        params = dict(params or {})
        next_url: str | None = url
        first = True
        pages = 0
        while next_url and pages < max_pages:
            resp = self.get(next_url, params=params if first else None)
            resp.raise_for_status()
            yield resp.json()
            pages += 1
            first = False
            next_url = resp.links.get("next", {}).get("url")


# --- source-specific client factories ---------------------------------------
def github_client() -> Client:
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = config.github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # Authenticated: 5000/hr -> a small spacing is plenty polite.
    return Client(base_url=config.endpoint("github_rest"), headers=headers,
                  rate=RateLimiter(0.1 if token else 1.2))


def github_graphql_client() -> Client:
    headers = {}
    token = config.github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return Client(base_url="", headers=headers, rate=RateLimiter(0.2))


def codeberg_client() -> Client:
    headers = {"Accept": "application/json"}
    token = config.codeberg_token()
    if token:
        headers["Authorization"] = f"token {token}"
    return Client(base_url=config.endpoint("codeberg_api"), headers=headers,
                  rate=RateLimiter(0.5))


def nvd_client() -> Client:
    headers = {}
    key = config.nvd_api_key()
    if key:
        headers["apiKey"] = key
    # NVD: 50 req / 30s with key (0.6s), 5 / 30s without (~6s). Be conservative.
    return Client(base_url="", headers=headers,
                  rate=RateLimiter(0.7 if key else 6.5))


def osv_client() -> Client:
    return Client(base_url="", rate=RateLimiter(0.2))


def deps_dev_client() -> Client:
    return Client(base_url=config.endpoint("deps_dev"), rate=RateLimiter(0.2))
