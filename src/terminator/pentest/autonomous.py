"""Autonomous pentest brain — adaptive attacks, not a fixed script.

Workflow:
  1. Recon (profile, API, crawl, form discovery)
  2. Build attack queue (multiple techniques per surface)
  3. Try approaches until confirmed or exhausted; chain auth attacks
  4. Passive baseline + report with techniques that worked
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from attack_engine import (
    build_attack_queue,
    confirmed_findings,
    discover_surfaces,
    run_attack_queue,
    run_auth_chains,
)
from memory_store import load_findings, now, save_findings, save_snapshot
from tools.analyze import analyze_target
from tools.api_routes import discover_api_paths, fetch_api_routes
from tools.http import paths_to_probe, probe_path, score_probe, web_base
from tools.playbook import _collect_snapshot, map_site
from tools.profile import profile_target
from tools.passive_skills import run_passive_suite


@dataclass
class Intel:
    base: str
    paths: list[dict] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    live_paths: set[str] = field(default_factory=set)
    has_forms: bool = False
    has_login: bool = False
    has_admin: bool = False
    ranked_focus: list[tuple] = field(default_factory=list)


@dataclass
class VulnHit:
    skill: str
    severity: str
    detail: str


def gather_intel(base: str) -> Intel:
    intel = Intel(base=base)
    for path in paths_to_probe(base):
        probe = probe_path(base, path)
        intel.paths.append(probe)
        status = probe.get("status")
        if status not in {"error", 404}:
            intel.live_paths.add(path.split("?", 1)[0])
        if probe.get("has_form"):
            intel.has_forms = True
        score, reasons = score_probe(probe)
        if score > 0:
            intel.ranked_focus.append((score, path, reasons))
    intel.ranked_focus.sort(key=lambda x: x[0], reverse=True)
    for path in discover_api_paths(base):
        intel.api_paths.append(path)
        intel.live_paths.add(path.split("?", 1)[0])
        if "login" in path:
            intel.has_login = True
        if "admin" in path:
            intel.has_admin = True
    return intel


def _recon(base: str, log_fn) -> tuple[str, Intel]:
    parts = []
    for name, fn in (
        ("profile", lambda: profile_target(base)),
        ("api", lambda: fetch_api_routes(base)),
        ("map", lambda: map_site(base)),
    ):
        log_fn(f"[recon] {name}")
        parts.append(f"=== recon: {name} ===\n{fn()}\n")
    intel = gather_intel(base)
    return "\n".join(parts), intel


def _findings_to_hits(findings: list[dict]) -> list[VulnHit]:
    hits = []
    for f in findings:
        hits.append(VulnHit(
            f"{f['category']}/{f['technique']}",
            f["severity"],
            f"{f['path']}?{f['param']}= — {f['note']}",
        ))
    return hits


def build_report(
    base: str,
    intel: Intel,
    attack_lines: list[str],
    auth_lines: list[str],
    findings: list[dict],
    chains: list[str],
    attempts: int,
    cycle: int,
) -> str:
    by_sev: dict[str, list] = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)

    lines = [
        "=== AUTONOMOUS ENGAGEMENT REPORT ===",
        f"target: {base}",
        f"cycle: {cycle}",
        f"time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"mode: adaptive (multi-technique, escalation, chains)",
        f"live surfaces: {len(intel.live_paths)}",
        f"attack attempts: {attempts}",
        f"confirmed: {len(findings)}",
        "",
        "=== CONFIRMED (technique that worked) ===",
    ]
    if findings:
        for f in findings:
            lines.append(
                f"  [{f['severity'].upper()}] {f['category']} via {f['technique']}\n"
                f"    {f['path']}?{f['param']}= payload={f['payload'][:60]}\n"
                f"    {f['note']}"
            )
    else:
        lines.append("  none confirmed this cycle")

    if chains:
        lines.append("")
        lines.append("=== ATTACK CHAINS ===")
        for c in chains:
            lines.append(f"  - {c}")

    lines.append("")
    lines.append("=== SEVERITY COUNTS ===")
    for sev in ("high", "medium", "low"):
        lines.append(f"  {sev.upper()}: {len(by_sev.get(sev, []))}")

    if intel.ranked_focus:
        lines.append("")
        lines.append("=== TOP RECON TARGETS ===")
        for score, path, reasons in intel.ranked_focus[:5]:
            lines.append(f"  [{score}] {path} — {', '.join(reasons)}")

    return "\n".join(lines)


def run_autonomous_engagement(
    target: str,
    cycle: int = 1,
    include_auth: bool = True,
    auth: dict | None = None,
    log_fn=print,
) -> str:
    base, err = web_base(target)
    if not base:
        return err

    auth = auth or {"username": "demo", "password": "demo"}

    log_fn(f"recon {base}")
    recon_body, intel = _recon(base, log_fn)

    surfaces = discover_surfaces(base, intel.live_paths)
    queue = build_attack_queue(surfaces, cycle=cycle)
    log_fn(f"attack plan: {len(queue)} attempts across {len(surfaces)} surfaces ({len(set(a.category for a in queue))} categories)")

    attack_output, attack_state = run_attack_queue(base, queue, log_fn=log_fn)

    auth_output = ""
    auth_state = None
    if include_auth and (intel.has_login or intel.has_admin or "/api/admin" in intel.live_paths):
        log_fn("auth chains — jwt variants, mass assignment, token follow-up")
        auth_output, auth_state = run_auth_chains(base, auth, log_fn=log_fn)

    log_fn("[passive] baseline hardening")
    passive_out = run_passive_suite(base)

    all_findings = confirmed_findings(attack_state)
    if auth_state:
        all_findings.extend(confirmed_findings(auth_state))
    chains = (auth_state.chains if auth_state else []) + attack_state.chains
    attempts = len(attack_state.attempts) + (len(auth_state.attempts) if auth_state else 0)

    analyze_out = ""
    if cycle == 1 or cycle % 6 == 0:
        log_fn("[analyze] merge intel")
        analyze_out = analyze_target(base)

    report = build_report(
        base, intel, attack_output, auth_output, all_findings, chains, attempts, cycle
    )

    snapshot = _collect_snapshot(base)
    snapshot["auth"] = load_findings().get("auth", {})
    snapshot["engagement"] = {"cycle": cycle, "confirmed": len(all_findings), "attempts": attempts}
    snap_path = save_snapshot(snapshot)

    save_findings({
        **load_findings(),
        "target": base,
        "updated": now(),
        "last_snapshot": str(snap_path),
        "engagement": {
            "cycle": cycle,
            "mode": "adaptive",
            "confirmed": all_findings,
            "chains": chains,
            "attempts": attempts,
            "surfaces": len(surfaces),
        },
    })

    auth_text = "\n".join(auth_output) if isinstance(auth_output, list) else auth_output
    raw_parts = [recon_body, "\n".join(attack_output), auth_text, passive_out, analyze_out]
    full = f"{report}\n\n=== RAW OUTPUT ===\n\n" + "\n".join(p for p in raw_parts if p) + f"\n\nsnapshot: {snap_path}"
    return full
