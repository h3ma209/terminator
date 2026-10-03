"""Non-interactive CLI for scripts and schedulers."""

from __future__ import annotations

import argparse
from pathlib import Path

from terminator import config
from terminator.agent.skill_mode import SKILL_TYPES
from terminator.tools import HANDLERS
from terminator.catalog import get_technique
from terminator.tools.http import sync_allowed_from_targets

DEFAULT_TARGET = "http://127.0.0.1:3000"

COMMANDS = {
    "playbook": ("run_playbook", "full scan pipeline"),
    "profile": ("profile_target", "ports, headers, robots, sitemap"),
    "analyze": ("analyze_target", "merged intel + focus ranking"),
    "api": ("fetch_api_routes", "discover API routes"),
    "auth": ("check_auth_flow", "login + JWT test"),
    "map": ("map_site", "crawl site pages"),
    "compare": ("compare_runs", "diff last two snapshots"),
    "findings": ("show_findings", "show session notes"),
    "inspect": ("inspect_url", "passive URL review"),
    "scan": ("scan_local", "localhost header check"),
    "skills": ("list_skills", "skill catalog"),
    "battery": ("run_skill_battery", "all skill checks"),
    "autonomous": ("run_autonomous_engagement", "full pentester brain cycle"),
    "takeover": ("run_takeover_engagement", "lab takeover — creds, services, webshell paths"),
    "xss": ("check_xss", "reflected XSS probe"),
    "sqli": ("check_sqli", "SQL injection probe"),
    "redirect": ("check_redirect", "open redirect probe"),
    "traversal": ("check_traversal", "path traversal probe"),
    "jwt": ("check_auth_bypass", "JWT + mass assignment"),
    "idor": ("check_idor", "IDOR probe"),
    "cors": ("check_cors", "CORS probe"),
    "ssrf": ("check_ssrf", "SSRF probe"),
    "cmdi": ("check_cmdi", "command injection probe"),
    "ssti": ("check_ssti", "SSTI probe"),
    "crlf": ("check_crlf", "CRLF probe"),
    "rate": ("check_rate_limit", "login rate limit"),
    "passive": ("run_passive_suite", "headers, csrf, leaks, clickjack, methods"),
    "probe": ("probe_xss", "one param + custom payload"),
}


def _apply_scope(target: str) -> None:
    sync_allowed_from_targets([target])
    if config.AUTOCONFIG_PATH.is_file():
        import json
        data = json.loads(config.AUTOCONFIG_PATH.read_text(encoding="utf-8"))
        config.ALLOW_LAN = bool(data.get("allow_lan", False))
        sync_allowed_from_targets(data.get("targets", []))


def main() -> int:
    config.ROOT = Path.cwd().resolve()

    parser = argparse.ArgumentParser(description="Run terminator tools without the chat loop.")
    parser.add_argument("command", nargs="?", help="tool to run")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="target URL")
    parser.add_argument("--user", default="demo", help="auth username")
    parser.add_argument("--pass", dest="password", default="demo", help="auth password")
    parser.add_argument("--out", help="write report to file")
    parser.add_argument("--path", default="", help="path for probe commands")
    parser.add_argument("--param", default="", help="query param for probe commands")
    parser.add_argument("--payload", default="", help="payload for probe commands")
    parser.add_argument("--skill", default="xss", help="probe skill type for probe command")
    parser.add_argument("--technique", default="", help="named technique from catalog (e.g. img_onerror, tautology)")
    args = parser.parse_args()

    if not args.command or args.command == "list":
        print("commands:")
        for name, (_, desc) in COMMANDS.items():
            print(f"  {name:<10} {desc}")
        return 0

    cmd = args.command.lower()
    if cmd not in COMMANDS:
        print(f"unknown command: {cmd}. try: python cli.py list")
        return 1

    _apply_scope(args.target)
    tool_name, _ = COMMANDS[cmd]
    handler = HANDLERS[tool_name]

    if tool_name in {"compare_runs", "show_findings", "list_skills"}:
        result = handler()
    elif tool_name == "probe_xss":
        skill = args.skill.lower()
        cfg = SKILL_TYPES.get(skill, SKILL_TYPES["xss"])
        path = args.path or cfg["defaults"]["path"]
        param = args.param or cfg["defaults"]["param"]
        if args.technique:
            tech = get_technique(skill, args.technique)
            payload = tech.payload if tech else args.payload
        else:
            payload = args.payload
        payload = payload or cfg["fallback_payload"]
        probe_name = cfg["probe_tool"]
        result = HANDLERS[probe_name](args.target, path, param, payload)
    elif tool_name == "check_auth_flow":
        result = handler(args.target, args.user, args.password)
    elif tool_name.startswith("check_") and args.payload:
        result = handler(args.target, payload=args.payload, path=args.path, param=args.param)
    elif tool_name in {"inspect_url", "scan_local"}:
        url = args.target if args.target.endswith("/") else args.target + "/"
        result = handler(url)
    else:
        result = handler(args.target)

    if args.out:
        Path(args.out).write_text(result, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(result)
    return 0
