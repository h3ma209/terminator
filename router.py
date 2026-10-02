"""Keyword router for auto-running tools."""

import re

from tools.analyze import analyze_target
from tools.api_routes import fetch_api_routes
from tools.playbook import (
    check_auth_flow,
    compare_runs,
    map_site,
    run_playbook,
    show_findings,
)
from tools.profile import profile_target
from tools.web import inspect_url, scan_local


def extract_url(text: str) -> str:
    match = re.search(r"https?://[^\s'\"<>]+", text, flags=re.I)
    if match:
        return match.group(0).rstrip(".,)")
    if re.search(r"127\.0\.0\.1|localhost", text, flags=re.I):
        return "http://127.0.0.1:3000"
    return "http://127.0.0.1:3000"


def prefetch_data(text: str) -> tuple[str, str] | None:
    lower = text.lower()
    url = extract_url(text)
    if "playbook" in lower or "full scan" in lower or "run all" in lower:
        return "run_playbook", run_playbook(url)
    if any(w in lower for w in ("compare", "diff", "regression")) and (
        "run" in lower or "snapshot" in lower or "127.0.0.1" in lower or "last" in lower
    ):
        return "compare_runs", compare_runs()
    if "findings" in lower or "session notes" in lower:
        return "show_findings", show_findings()
    if any(w in lower for w in ("auth flow", "check auth", "jwt", "login flow")):
        return "check_auth_flow", check_auth_flow(url)
    if any(w in lower for w in ("map site", "site map", "crawl", "map pages")):
        return "map_site", map_site(url)
    if "api route" in lower or "api routes" in lower or "fetch api" in lower:
        return "fetch_api_routes", fetch_api_routes(url)
    analyze_words = ("analyze", "merge", "priorit", "where to target", "where to focus", "focus area")
    profile_words = ("profile", "robots", "sitemap", "ports", "recon", "target")
    local_words = ("127.0.0.1", "localhost", "http", "site", "target")
    if any(w in lower for w in analyze_words) and any(w in lower for w in local_words):
        return "analyze_target", analyze_target(url)
    if any(w in lower for w in profile_words) and any(w in lower for w in local_words):
        if not any(w in lower for w in analyze_words):
            return "profile_target", profile_target(url)
    if "inspect" in lower and any(w in lower for w in local_words):
        return "inspect_url", inspect_url(url)
    if "scan" in lower and ("127.0.0.1" in lower or "localhost" in lower):
        return "scan_local", scan_local(url)
    return None


def wants_tools(text: str) -> bool:
    lowered = text.lower()
    hints = (
        "file", "code", "read", "list", "dir", "folder", "bug", "function",
        "project", "workspace", "script", "error", "line ", ".py", ".js", ".html",
        "http", "localhost", "127.0.0.1", "site", "page", "server",
        "scan", "vuln", "header", "security", "inspect", "cookie", "tls", "https",
        "profile", "port", "target", "recon", "analyze", "merge", "focus", "priorit", "api",
        "playbook", "auth", "jwt", "map", "compare", "findings",
    )
    return any(hint in lowered for hint in hints)
