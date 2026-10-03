"""Program scope — in-scope assets, OOS, rate limits."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ProgramScope:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_private: bool = False
    rate_delay_ms: int = 200
    destructive_ok: bool = False
    max_requests_per_minute: int = 120

    @classmethod
    def from_config(cls, cfg: dict | None) -> ProgramScope:
        if not cfg:
            return cls()
        scope = cfg.get("scope") or {}
        return cls(
            in_scope=list(scope.get("in_scope") or cfg.get("targets") or []),
            out_of_scope=list(scope.get("out_of_scope") or []),
            allow_private=bool(scope.get("allow_private") or cfg.get("allow_lan")),
            rate_delay_ms=int(scope.get("rate_delay_ms", 200)),
            destructive_ok=bool(scope.get("destructive_ok", False)),
            max_requests_per_minute=int(scope.get("max_requests_per_minute", 120)),
        )


def _host_match(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower()
    host = host.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if "://" in pattern:
        parsed = urlparse(pattern)
        if parsed.hostname:
            return _host_match(parsed.hostname, host)
    return pattern == host or pattern.rstrip("/") == host


def _url_match(pattern: str, url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.hostname:
        return False
    pat = pattern.strip()
    if "://" in pat:
        norm = pat.rstrip("/")
        return url.rstrip("/").startswith(norm) or url.startswith(norm + "/")
    return _host_match(pat, parsed.hostname)


def is_out_of_scope(url: str, scope: ProgramScope) -> bool:
    for pat in scope.out_of_scope:
        if _url_match(pat, url):
            return True
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        if ipaddress.ip_address(host).is_private and not scope.allow_private:
            # Align with http.is_allowed_host — explicit in_scope or open scope OK
            if scope.in_scope and any(_url_match(p, url) for p in scope.in_scope):
                return False
            if not scope.in_scope:
                return False  # no scope config = allow (caller must gate via is_allowed_host)
            return True
    except ValueError:
        pass
    return False


def is_in_scope(url: str, scope: ProgramScope) -> bool:
    if is_out_of_scope(url, scope):
        return False
    if not scope.in_scope:
        return True
    return any(_url_match(p, url) for p in scope.in_scope)


def assert_in_scope(url: str, scope: ProgramScope) -> str | None:
    if not is_in_scope(url, scope):
        return f"blocked: {url} out of program scope"
    return None
