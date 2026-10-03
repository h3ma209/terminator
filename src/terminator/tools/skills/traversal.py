"""Path traversal / LFI probes for localhost targets."""

import re

from terminator.tools.http import web_base
from terminator.tools.probe_http import MAX_PAYLOAD_LEN, build_get_url, fetch_get, save_probe

DEFAULT_PROBE = "../../../etc/passwd"
TRAVERSAL_HINTS = (
    r"root:.*?:/bin/",
    r"/etc/passwd",
    r"boot\.ini",
    r"\[extensions\]",
    r"windows/system32",
)


def _analyze(injected: dict, payload: str) -> dict:
    body = injected.get("body") or ""
    signals = []
    for pat in TRAVERSAL_HINTS:
        if re.search(pat, body, flags=re.I):
            signals.append(f"file content hint: {pat}")
    if payload and payload in body:
        signals.append("payload echoed in body")
    if injected.get("status") == 200 and len(body) > 20 and signals:
        pass
    vulnerable = bool(signals)
    return {"vulnerable": vulnerable, "signals": signals}


def probe_traversal(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    if not payload or not param or not path:
        return "error: path, param, and payload are required"
    if len(payload) > MAX_PAYLOAD_LEN:
        return f"error: payload too long (max {MAX_PAYLOAD_LEN})"

    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path

    probe_url = build_get_url(base, path, param, payload)
    injected = fetch_get(probe_url)
    result = _analyze(injected, payload)

    lines = [
        "=== probe_traversal ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {payload}",
        f"status: {injected.get('status')}",
        f"vulnerable: {result['vulnerable']}",
        f"signals: {', '.join(result['signals']) or 'none'}",
        f"url: {probe_url}",
    ]
    if result["vulnerable"]:
        lines.append(f"snippet: {injected.get('body', '')[:200]}")

    save_probe("probe_traversal", {
        "target": base,
        "path": path,
        "param": param,
        "payload": payload[:120],
        "vulnerable": result["vulnerable"],
        "signals": result["signals"],
        "contexts": result["signals"],
    })
    return "\n".join(lines)


def check_traversal(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    base, err = web_base(target)
    if not base:
        return err

    use_payload = payload or DEFAULT_PROBE
    tpath = path.split("?", 1)[0] if path else "/files"
    tparam = param or "name"
    result = probe_traversal(base, tpath, tparam, use_payload)
    return "=== path traversal check ===\n" + result.split("=== probe_traversal ===", 1)[-1].lstrip()
