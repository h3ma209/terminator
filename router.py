"""Keyword router — runs tools directly, bypasses the model."""

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
from tools.web import fetch_url, inspect_url, scan_local
from tools.workspace import list_dir, read_file
from skill_mode import wants_skill_mode
from targets import extract_url
from tools.xss import check_xss


def check_login_apis(target: str) -> str:
    api = fetch_api_routes(target)
    auth = check_auth_flow(target)
    return f"{api}\n\n=== auth flow ===\n{auth}"


def _wants_login_api_check(lower: str) -> bool:
    if re.search(r"\b(login|auth|jwt)\b", lower) and re.search(r"\b(api|apis|endpoint)\b", lower):
        return True
    hints = (
        "login api", "login apis", "api login", "check login",
        "auth api", "login endpoint", "login endpoints", "test login",
    )
    return any(h in lower for h in hints)


def prefetch_data(text: str) -> tuple[str, str] | None:
    """Match user intent and run the tool. Returns (tool_name, output)."""
    lower = text.lower().strip()
    url = extract_url(text)

    # explicit commands
    if lower in {"/help", "help"}:
        return None
    if "playbook" in lower or "full scan" in lower or "run all" in lower:
        return "run_playbook", run_playbook(url)
    if "compare" in lower or "diff" in lower:
        return "compare_runs", compare_runs()
    if "findings" in lower or "session notes" in lower:
        return "show_findings", show_findings()
    if _wants_login_api_check(lower):
        return "check_login_apis", check_login_apis(url)
    if any(w in lower for w in ("auth flow", "check auth", "jwt", "login flow")):
        return "check_auth_flow", check_auth_flow(url)
    if any(w in lower for w in ("map site", "site map", "crawl", "map pages", "crawl site")):
        return "map_site", map_site(url)
    if any(w in lower for w in ("api route", "api routes", "fetch api", "endpoints")):
        return "fetch_api_routes", fetch_api_routes(url)
    if any(w in lower for w in ("analyze", "priorit", "where to focus", "where to target", "focus area")):
        return "analyze_target", analyze_target(url)
    if any(w in lower for w in ("xss", "cross-site", "cross site", "reflected")) and not wants_skill_mode(text):
        return "check_xss", check_xss(url)

    # profile-ish (broad)
    if any(w in lower for w in (
        "profile", "robots", "sitemap", "ports", "recon", "banner",
        "check site", "check the site", "look at", "look at site",
        "scan site", "scan the", "what ports", "show ports",
    )):
        return "profile_target", profile_target(url)

    # inspect / scan
    if "inspect" in lower or "headers" in lower or "security check" in lower:
        page = url if url.endswith("/") else url + "/"
        return "inspect_url", inspect_url(page)
    if "scan" in lower and ("127.0.0.1" in lower or "localhost" in lower or "3000" in lower):
        page = url if url.endswith("/") else url + "/"
        return "scan_local", scan_local(page)

    # fetch any url mentioned
    if re.search(r"https?://", text, flags=re.I) and any(w in lower for w in ("fetch", "get", "open", "read", "curl", "wget")):
        return "fetch_url", fetch_url(url)

    # workspace
    if lower.startswith("list ") or lower.startswith("ls ") or "list files" in lower or "list dir" in lower:
        path = text.split(maxsplit=1)[1] if " " in text.strip() else "."
        return "list_dir", list_dir(path.strip())
    if lower.startswith("read ") or lower.startswith("cat ") or lower.startswith("show file "):
        path = text.split(maxsplit=1)[1].strip()
        return "read_file", read_file(path)

    # bare localhost mention + action verb → profile
    if re.search(r"127\.0\.0\.1|localhost|:3000", lower) and any(w in lower for w in (
        "check", "scan", "test", "look", "review", "audit", "info", "status",
    )):
        return "profile_target", profile_target(url)

    return None


def wants_tools(text: str) -> bool:
    """Only used if prefetch missed and model path is taken."""
    return prefetch_data(text) is not None
