"""Command injection and SSTI probes."""

import re

from terminator.tools.http import web_base
from terminator.tools.probe_http import build_get_url, fetch_get, save_probe
from terminator.catalog import check_with_variations, default_payload


def probe_cmdi(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/ping"
    param = param or "host"
    probe_val = payload or "127.0.0.1;id"
    injected = fetch_get(build_get_url(base, path, param, probe_val))
    body = injected.get("body") or ""
    signals = []
    if re.search(r"uid=\d+\(", body):
        signals.append("shell output pattern in response")
    if "shell metacharacters" in body:
        signals.append("server admits shell metacharacters")
    if probe_val.split(";")[0] in body:
        signals.append("command echoed")
    vulnerable = bool(signals)

    lines = [
        "=== probe_cmdi ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {probe_val}",
        f"status: {injected.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"snippet: {body[:200]}",
    ]
    save_probe("probe_cmdi", {
        "target": base, "path": path, "param": param,
        "payload": probe_val[:120], "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_cmdi(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    return check_with_variations(
        "cmdi", "command injection check", probe_cmdi,
        target, path or "/ping", param or "host", payload,
    )


def probe_ssti(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/render"
    param = param or "template"
    probe_val = payload or "{{7*7}}"
    injected = fetch_get(build_get_url(base, path, param, probe_val))
    body = injected.get("body") or ""
    signals = []
    if '"rendered":"49"' in body.replace(" ", "") or '"rendered": "49"' in body:
        signals.append("template expression evaluated (49)")
    if "[eval:" in body:
        signals.append("template eval marker in response")
    if probe_val in body and "49" not in body:
        signals.append("template reflected only")
    vulnerable = "49" in body and "7*7" not in body.split("rendered")[-1][:20]

    lines = [
        "=== probe_ssti ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {probe_val}",
        f"status: {injected.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"snippet: {body[:200]}",
    ]
    save_probe("probe_ssti", {
        "target": base, "path": path, "param": param,
        "payload": probe_val[:120], "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_ssti(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    return check_with_variations(
        "ssti", "SSTI check", probe_ssti,
        target, path or "/render", param or "template", payload,
    )
