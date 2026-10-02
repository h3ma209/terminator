"""Non-interactive CLI for scripts and schedulers.

Examples:
  python cli.py playbook http://127.0.0.1:3000
  python cli.py profile
  python cli.py auth --user demo --pass demo
  python cli.py list
"""

import argparse
import sys
from pathlib import Path

import config
from tools import HANDLERS

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
    "xss": ("check_xss", "reflected XSS probe"),
    "probe": ("probe_xss", "one param + custom payload"),
    "skills": ("list_skills", "skill catalog"),
}


def main() -> int:
    config.ROOT = Path.cwd().resolve()

    parser = argparse.ArgumentParser(description="Run terminator tools without the chat loop.")
    parser.add_argument("command", nargs="?", help="tool to run (playbook, profile, auth, ...)")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="target URL")
    parser.add_argument("--user", default="demo", help="auth username")
    parser.add_argument("--pass", dest="password", default="demo", help="auth password")
    parser.add_argument("--out", help="write report to file")
    parser.add_argument("--path", default="/search", help="path for probe_xss")
    parser.add_argument("--param", default="q", help="query param for probe_xss")
    parser.add_argument("--payload", default="<script>alert(1)</script>", help="XSS payload for probe_xss")
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

    tool_name, _ = COMMANDS[cmd]
    handler = HANDLERS[tool_name]

    if tool_name == "compare_runs":
        result = handler()
    elif tool_name == "show_findings":
        result = handler()
    elif tool_name == "list_skills":
        result = handler()
    elif tool_name == "probe_xss":
        result = handler(args.target, args.path, args.param, args.payload)
    elif tool_name == "check_xss" and args.payload:
        result = handler(args.target, payload=args.payload, path=args.path, param=args.param)
    elif tool_name == "check_auth_flow":
        result = handler(args.target, args.user, args.password)
    elif tool_name == "inspect_url":
        url = args.target if args.target.endswith("/") else args.target + "/"
        result = handler(url)
    elif tool_name == "scan_local":
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


if __name__ == "__main__":
    raise SystemExit(main())
