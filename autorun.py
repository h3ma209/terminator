"""Fully autonomous scan loop — no chat, no prompts.

Passive scans by default. Auth login test runs only on schedule.

  python autorun.py              loop forever
  python autorun.py --once       single cycle
  python autorun.py --interval 300
  python autorun.py --full       include auth + full analyze each cycle
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import config
from memory_store import list_snapshots, load_findings, save_findings, save_snapshot
from tools.analyze import analyze_target
from tools.api_routes import fetch_api_routes
from tools.http import web_base
from tools.playbook import _collect_snapshot, check_auth_flow, compare_runs, map_site
from tools.profile import profile_target

AUTOCONFIG_PATH = config.AGENT_DIR / "autoconfig.json"
LOG_PATH = config.AGENT_DIR / "autorun.log"
MIN_INTERVAL = 60

DEFAULT_CONFIG = {
    "targets": ["http://127.0.0.1:3000"],
    "interval_seconds": 3600,
    "run_on_start": True,
    "compare_after_run": True,
    "steps": ["profile", "api", "map"],
    "auth_every_cycles": 12,
    "auth": {"username": "demo", "password": "demo"},
}


def log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}"
    print(line)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def load_autoconfig() -> dict:
    if not AUTOCONFIG_PATH.is_file():
        AUTOCONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n", encoding="utf-8")
        log(f"created default config: {AUTOCONFIG_PATH}")
    data = json.loads(AUTOCONFIG_PATH.read_text(encoding="utf-8"))
    return {**DEFAULT_CONFIG, **data}


def target_up(target: str) -> bool:
    base, err = web_base(target)
    if not base:
        log(f"skip {target}: {err}")
        return False
    try:
        urllib.request.urlopen(base + "/health", timeout=3)
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        try:
            urllib.request.urlopen(base + "/", timeout=3)
            return True
        except (urllib.error.URLError, TimeoutError, OSError):
            log(f"skip {target}: not reachable")
            return False


def run_autorun_scan(target: str, cfg: dict, cycle: int, full: bool) -> str:
    base, err = web_base(target)
    if not base:
        return err

    if full:
        steps = ["profile", "api", "auth", "map", "analyze"]
    else:
        steps = list(cfg.get("steps", ["profile", "api", "map"]))
        auth_every = cfg.get("auth_every_cycles", 12)
        if auth_every and cycle % auth_every == 0:
            if "auth" not in steps:
                steps.append("auth")
        else:
            steps = [s for s in steps if s != "auth"]

    auth_cfg = cfg.get("auth", {})
    lines = [f"target: {base}", f"cycle: {cycle}", f"steps: {', '.join(steps)}", ""]
    for step in steps:
        log(f"  {step}")
        if step == "profile":
            body = profile_target(base)
        elif step == "api":
            body = fetch_api_routes(base)
        elif step == "auth":
            body = check_auth_flow(base, auth_cfg.get("username", "demo"), auth_cfg.get("password", "demo"))
        elif step == "map":
            body = map_site(base)
        elif step == "analyze":
            body = analyze_target(base)
        else:
            body = f"unknown step: {step}"
        lines.append(f"=== {step} ===")
        lines.append(body)
        lines.append("")

    snapshot = _collect_snapshot(base)
    if "auth" not in steps:
        snapshot["auth"] = load_findings().get("auth", {})
    snap_path = save_snapshot(snapshot)
    save_findings({
        **load_findings(),
        "target": base,
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_snapshot": str(snap_path),
        "open_ports": snapshot["open_ports"],
        "missing_headers": snapshot["missing_headers"],
        "api_routes": snapshot["api_routes"],
        "focus": snapshot["focus"],
    })
    lines.insert(3, f"snapshot: {snap_path}")
    return "\n".join(lines).strip()


_busy = False


def run_cycle(cfg: dict, cycle: int, full: bool) -> None:
    global _busy
    if _busy:
        log("skip cycle — previous scan still running")
        return
    _busy = True
    try:
        log(f"cycle {cycle} start — {len(cfg['targets'])} target(s)")
        before = len(list_snapshots())
        for target in cfg["targets"]:
            if not target_up(target):
                continue
            log(f"scan {target}")
            try:
                report = run_autorun_scan(target, cfg, cycle, full)
                config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                (config.REPORTS_DIR / "latest.txt").write_text(report, encoding="utf-8")
                log(f"done {target}")
            except Exception as exc:
                log(f"error {target}: {exc}")
        if cfg.get("compare_after_run") and len(list_snapshots()) >= 2 and len(list_snapshots()) > before:
            diff = compare_runs()
            if "no differences" not in diff:
                log("real changes since last run:")
                for line in diff.splitlines():
                    if line.strip():
                        log(f"  {line}")
            else:
                log("no real changes")
    finally:
        _busy = False


def main() -> int:
    config.ROOT = Path.cwd().resolve()
    parser = argparse.ArgumentParser(description="Autonomous terminator scan loop.")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--full", action="store_true", help="auth + analyze every cycle")
    parser.add_argument("--interval", type=int, help="seconds between cycles")
    args = parser.parse_args()

    cfg = load_autoconfig()
    interval = args.interval or cfg.get("interval_seconds", 3600)
    if interval < MIN_INTERVAL:
        log(f"interval {interval}s too low — using {MIN_INTERVAL}s minimum")
        interval = MIN_INTERVAL

    log(f"autorun started — interval {interval}s — passive steps: {cfg.get('steps')}")
    if not args.full:
        log(f"auth test every {cfg.get('auth_every_cycles', 12)} cycles (use --full to test each cycle)")

    cycle = 1
    if cfg.get("run_on_start", True) or args.once:
        run_cycle(cfg, cycle, args.full)
    if args.once:
        log("autorun finished (--once)")
        return 0

    while True:
        log(f"sleep {interval}s")
        time.sleep(interval)
        cycle += 1
        run_cycle(cfg, cycle, args.full)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("autorun stopped")
        raise SystemExit(0)
