"""General web fetch and passive URL inspection."""

import re
import urllib.request
from urllib.parse import urlparse

from terminator import config
from terminator.tools.http import NoRedirect, cookie_notes, is_allowed_host, page_notes, tls_note


def fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "blocked: url must be http or https"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read(config.MAX_READ).decode("utf-8", errors="replace")
            return f"status {res.status}\n{body}"
    except Exception as exc:
        return f"error: {exc}"


def scan_local(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname or not is_allowed_host(parsed.hostname):
        return "blocked: target not in scope (allow_lan or add to targets)"
    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=10) as res:
            body = res.read(4000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in res.headers.items()}
            status = res.status
    except Exception as exc:
        return f"error: {exc}"
    lines = [f"url: {url}", f"status: {status}", "headers:"]
    for key in sorted(headers):
        lines.append(f"  {key}: {headers[key]}")
    lines.append("passive findings:")
    for name in config.HEADER_CHECKS:
        if name not in headers:
            lines.append(f"  missing {name}")
    if "server" in headers:
        lines.append("  server header discloses software")
    if "<script" in body.lower():
        lines.append("  page contains a script tag")
    else:
        lines.append("  no script tag in the first 4000 bytes")
    return "\n".join(lines)


def inspect_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "blocked: url must be http or https"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read(config.MAX_READ).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in res.headers.items()}
            status = res.status
            final = res.geturl()
    except Exception as exc:
        return f"error: {exc}"
    lines = [f"requested: {url}", f"final: {final}", f"status: {status}"]
    if parsed.scheme == "http":
        lines.append("page is served over http")
    lines.append("headers missing:")
    missing = [name for name in config.HEADER_CHECKS if name not in headers]
    lines.extend(f"  {name}" for name in missing)
    if not missing:
        lines.append("  none from the checklist")
    if "server" in headers or "x-powered-by" in headers:
        lines.append("response identifies server software")
    lines.append("cookies:")
    lines.extend(f"  {note}" for note in cookie_notes(headers))
    if parsed.scheme == "https":
        port = parsed.port or 443
        lines.append(tls_note(parsed.hostname, port))
    lines.append("page:")
    lines.extend(f"  {note}" for note in page_notes(body, final))
    return "\n".join(lines)
