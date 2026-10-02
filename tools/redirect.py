"""Open redirect probes for localhost targets."""

import re

from tools.http import paths_to_probe, web_base
from tools.probe_http import MAX_PAYLOAD_LEN, build_get_url, fetch_get, save_probe

DEFAULT_PROBE = "https://evil.example/phish"
REDIRECT_PARAMS = ("url", "next", "redirect", "return", "dest", "continue")


def _analyze(injected: dict, payload: str) -> dict:
    status = injected.get("status")
    location = (injected.get("headers") or {}).get("location", "")
    signals = []

    if status in {301, 302, 303, 307, 308}:
        signals.append(f"redirect status {status}")
    if location:
        signals.append(f"location header: {location}")
    if payload and payload in location:
        signals.append("payload reflected in location")
    if location.startswith("//") or re.match(r"https?://", location):
        if "127.0.0.1" not in location and "localhost" not in location:
            signals.append("external redirect")

    vulnerable = bool(signals) and bool(location)
    return {"vulnerable": vulnerable, "signals": signals, "location": location}


def probe_redirect(target: str, path: str, param: str, payload: str) -> str:
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
    injected = fetch_get(probe_url, follow_redirects=False)
    result = _analyze(injected, payload)

    lines = [
        "=== probe_redirect ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {payload}",
        f"status: {injected.get('status')}",
        f"vulnerable: {result['vulnerable']}",
        f"location: {result.get('location') or 'none'}",
        f"signals: {', '.join(result['signals']) or 'none'}",
        f"url: {probe_url}",
    ]

    save_probe("probe_redirect", {
        "target": base,
        "path": path,
        "param": param,
        "payload": payload[:120],
        "vulnerable": result["vulnerable"],
        "signals": result["signals"],
        "contexts": result["signals"],
        "location": result.get("location", ""),
    })
    return "\n".join(lines)


def check_redirect(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    base, err = web_base(target)
    if not base:
        return err

    use_payload = payload or DEFAULT_PROBE
    targets = []
    if path and param:
        targets = [(path.split("?", 1)[0], param)]
    else:
        targets.append(("/redirect", "url"))
        for p in paths_to_probe(base):
            if "redirect" in p.lower():
                for rp in REDIRECT_PARAMS:
                    targets.append((p.split("?", 1)[0], rp))

    seen = set()
    probes = []
    for tpath, tparam in targets:
        key = (tpath, tparam)
        if key in seen:
            continue
        seen.add(key)
        probes.append(probe_redirect(base, tpath, tparam, use_payload))

    vuln = [p for p in probes if "vulnerable: True" in p]
    lines = [
        "=== open redirect check ===",
        f"base: {base}",
        f"probes: {len(probes)}",
        f"payload: {use_payload}",
        "",
        f"LIKELY VULNERABLE: {len(vuln)}",
    ]
    for block in probes:
        if "vulnerable: True" in block:
            for line in block.splitlines():
                if line.startswith(("request:", "location:", "url:")):
                    lines.append(f"  {line}")
    if not vuln:
        lines.append("  none found")
    return "\n".join(lines)
