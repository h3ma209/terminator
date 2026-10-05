"""Passive security checks: CSRF, headers, leaks, clickjacking, HTTP methods."""

import re
import urllib.request

from terminator import config
from terminator.core.memory import load_findings, now, save_findings
from terminator.tools.http import paths_to_probe, probe_path, request_method, web_base
from terminator.tools.probe_http import fetch_get

SECRET_PATTERNS = (
    r"cyborg-dev-secret",
    r"api[_-]?key\s*[:=]\s*['\"]?\w+",
    r"password\s*[:=]\s*['\"]?\w+",
    r"BEGIN (RSA |EC )?PRIVATE KEY",
    r"stack trace",
    r"at \w+\([^)]+\.js:\d+",
)


def check_csrf(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    issues = []
    for path in paths_to_probe(base):
        if not path.endswith(".html") and path not in {"/", "/search"}:
            continue
        url = base.rstrip("/") + path
        data = fetch_get(url)
        body = data.get("body") or ""
        for form in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, flags=re.I | re.S):
            attrs, inner = form.group(1), form.group(2)
            method = re.search(r'method=["\']([^"\']+)', attrs, flags=re.I)
            m = (method.group(1) if method else "get").lower()
            if m not in {"post", "put", "delete"}:
                continue
            has_token = bool(re.search(r"csrf|token|_token", inner, flags=re.I))
            action = re.search(r'action=["\']([^"\']*)', attrs, flags=re.I)
            act = action.group(1) if action else path
            if not has_token:
                issues.append(f"{act} ({m}) missing csrf token")
    lines = [
        "=== CSRF check ===",
        f"target: {base}",
        f"forms flagged: {len(issues)}",
    ]
    if issues:
        lines.extend(f"  - {item}" for item in issues)
    else:
        lines.append("  no state-changing forms without tokens (GET forms ignored)")
    save_findings({**load_findings(), "target": base, "updated": now(), "csrf": {"issues": issues}})
    return "\n".join(lines)


def check_security_headers(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    data = fetch_get(base.rstrip("/") + "/")
    headers = data.get("headers") or {}
    missing = [h for h in config.HEADER_CHECKS if h not in headers]
    present = [h for h in config.HEADER_CHECKS if h in headers]
    score = max(0, 100 - len(missing) * 15)
    lines = [
        "=== security headers ===",
        f"target: {base}",
        f"score: {score}/100",
        f"missing: {', '.join(missing) or 'none'}",
        f"present: {', '.join(present) or 'none'}",
    ]
    if "server" in headers:
        lines.append(f"  server leak: {headers['server']}")
    hdr_text = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items())[:20])
    save_findings({**load_findings(), "target": base, "updated": now(), "security_headers": {
        "score": score, "missing": missing,
        "request_raw": f"GET {base}/",
        "response_raw": hdr_text,
    }})
    return "\n".join(lines)


def check_sensitive_leak(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    hits = []
    for path in paths_to_probe(base):
        data = fetch_get(base.rstrip("/") + path)
        body = data.get("body") or ""
        for pat in SECRET_PATTERNS:
            if re.search(pat, body, flags=re.I):
                hits.append(f"{path}: pattern /{pat}/")
    lines = [
        "=== sensitive data leak ===",
        f"target: {base}",
        f"hits: {len(hits)}",
    ]
    lines.extend(f"  - {h}" for h in hits[:12] or ["none"])
    save_findings({**load_findings(), "target": base, "updated": now(), "leaks": hits})
    return "\n".join(lines)


def check_clickjacking(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    data = fetch_get(base.rstrip("/") + "/")
    headers = data.get("headers") or {}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    signals = []
    if not xfo:
        signals.append("missing X-Frame-Options")
    if "frame-ancestors" not in csp:
        signals.append("missing CSP frame-ancestors")
    vulnerable = bool(signals)
    lines = [
        "=== clickjacking check ===",
        f"target: {base}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'protected'}",
    ]
    hdr_text = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items())[:20])
    save_findings({**load_findings(), "target": base, "updated": now(), "clickjacking": {
        "vulnerable": vulnerable, "signals": signals,
        "request_raw": f"GET {base}/",
        "response_raw": hdr_text,
    }})
    return "\n".join(lines)


def check_http_methods(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    routes = ["/api/login", "/api/profile", "/api/admin", "/health"]
    findings = []
    for path in routes:
        url = base.rstrip("/") + path
        for method in ("OPTIONS", "PUT", "DELETE"):
            result = request_method(url, method, b"{}" if method != "OPTIONS" else None)
            status = result.get("status")
            if status not in {405, 404, 401, 403} and method == "DELETE":
                findings.append(f"{method} {path} -> {status} (unexpected allow)")
            if method == "OPTIONS" and status in {200, 204}:
                findings.append(f"OPTIONS {path} -> {status}")
    lines = [
        "=== HTTP methods check ===",
        f"target: {base}",
        f"findings: {len(findings)}",
    ]
    lines.extend(f"  - {f}" for f in findings or ["no risky method exposure"])
    save_findings({**load_findings(), "target": base, "updated": now(), "http_methods": findings})
    return "\n".join(lines)


def build_passive_findings(data: dict) -> list[dict]:
    """Structured passive findings from saved check results."""
    findings: list[dict] = []
    target = data.get("target") or "TARGET"

    sh = data.get("security_headers") or {}
    missing = sh.get("missing") or []
    score = sh.get("score", 100)
    if missing:
        findings.append({
            "category": "security_headers",
            "technique": "header_gaps",
            "severity": "low" if score < 70 else "info",
            "path": "/",
            "param": "headers",
            "payload": "",
            "note": f"hardening score {score}/100 — missing {', '.join(missing)}",
            "signals": missing,
            "phase": "passive",
            "triggered_by": f"passive/check_security_headers — score {score}/100, missing {', '.join(missing[:5])}",
            "repro_steps": [
                f"curl -sI {target}/",
                "Check response headers for X-Content-Type-Options, CSP, X-Frame-Options, HSTS",
                f"Confirm score {score}/100 — missing: {', '.join(missing)}",
            ],
            "request_raw": sh.get("request_raw", f"GET {target}/"),
            "response_raw": sh.get("response_raw", ""),
        })

    ck = data.get("clickjacking") or {}
    if ck.get("vulnerable"):
        # Merge into security_headers finding when both present (same root cause)
        merged = False
        for f in findings:
            if f.get("category") == "security_headers":
                f.setdefault("signals", []).extend([
                    "clickjacking possible", "missing X-Frame-Options", "missing CSP frame-ancestors",
                ])
                f["signals"] = list(dict.fromkeys(f["signals"]))
                f["note"] += "; clickjacking possible (no frame protection)"
                f["triggered_by"] += " + check_clickjacking"
                merged = True
                break
        if not merged:
            findings.append({
                "category": "clickjacking",
                "technique": "missing_frame_protection",
                "severity": "medium",
                "path": "/",
                "param": "headers",
                "payload": "",
                "note": "missing X-Frame-Options and/or CSP frame-ancestors",
                "signals": ["clickjacking possible", "missing X-Frame-Options", "missing CSP frame-ancestors"],
                "phase": "passive",
                "triggered_by": "passive/check_clickjacking — vulnerable: True, missing frame protection headers",
                "repro_steps": [
                    f"curl -sI {target}/",
                    "Verify X-Frame-Options and Content-Security-Policy frame-ancestors are absent",
                ],
                "request_raw": ck.get("request_raw", ""),
                "response_raw": ck.get("response_raw", ""),
            })

    for hit in data.get("leaks") or []:
        findings.append({
            "category": "sensitive_leak",
            "technique": "pattern_match",
            "severity": "medium",
            "path": hit.split(":", 1)[0] if ":" in hit else "/",
            "param": "body",
            "payload": "",
            "note": hit,
            "signals": [hit],
            "phase": "passive",
        })

    for item in data.get("http_methods") or []:
        if "DELETE" in item:
            findings.append({
                "category": "http_methods",
                "technique": "delete_allowed",
                "severity": "medium",
                "path": item.split()[1] if len(item.split()) > 1 else "/",
                "param": "method",
                "payload": "DELETE",
                "note": item,
                "signals": [item],
                "phase": "passive",
            })

    for issue in (data.get("csrf") or {}).get("issues") or []:
        findings.append({
            "category": "csrf",
            "technique": "missing_token",
            "severity": "medium",
            "path": issue.split()[0] if issue else "/",
            "param": "form",
            "payload": "",
            "note": issue,
            "signals": [issue],
            "phase": "passive",
        })

    return findings


def run_passive_suite(target: str) -> str:
    checks = (
        check_security_headers,
        check_csrf,
        check_sensitive_leak,
        check_clickjacking,
        check_http_methods,
    )
    parts = [fn(target) for fn in checks]
    return "\n\n".join(parts)


def run_passive_suite_with_findings(target: str) -> tuple[str, list[dict]]:
    text = run_passive_suite(target)
    return text, build_passive_findings(load_findings())
