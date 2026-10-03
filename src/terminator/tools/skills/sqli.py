"""SQL injection probes for localhost targets."""

import json
import re

from terminator.tools.http import paths_to_probe, web_base
from terminator.tools.probe_http import MAX_PAYLOAD_LEN, build_get_url, fetch_get, save_probe

DEFAULT_PROBE = "' OR '1'='1"
BASELINE = "1"
ERROR_PATTERNS = (
    r"sql syntax",
    r"sqlite",
    r"mysql",
    r"postgresql",
    r"ora-\d",
    r"syntax error",
    r"unclosed quotation",
    r"quoted string not properly terminated",
    r"near \"",
)
BYPASS_HINTS = ("all rows", "multiple users", "admin", '"users"')


def _analyze(baseline: dict, injected: dict, payload: str) -> dict:
    bbody = baseline.get("body") or ""
    pbody = injected.get("body") or ""
    signals = []

    for pat in ERROR_PATTERNS:
        if re.search(pat, pbody, flags=re.I) and not re.search(pat, bbody, flags=re.I):
            signals.append(f"error pattern: {pat}")

    if baseline.get("status") != injected.get("status"):
        signals.append(f"status change {baseline.get('status')} -> {injected.get('status')}")

    try:
        bjson = json.loads(bbody) if bbody.lstrip().startswith("{") else {}
        pjson = json.loads(pbody) if pbody.lstrip().startswith("{") else {}
    except json.JSONDecodeError:
        bjson, pjson = {}, {}

    if pjson.get("query") and payload in str(pjson.get("query", "")):
        signals.append("payload echoed in query field")

    if pjson.get("users") and not bjson.get("users"):
        signals.append("extra rows returned")

    lower = pbody.lower()
    for hint in BYPASS_HINTS:
        if hint in lower and hint not in bbody.lower():
            signals.append(f"response hint: {hint}")

    if len(pbody) > len(bbody) + 40 and payload.lower().replace(" ", "") in pbody.lower().replace(" ", ""):
        signals.append("large response delta with payload present")

    vulnerable = bool(signals)
    return {
        "vulnerable": vulnerable,
        "signals": signals,
        "note": "likely sqli" if vulnerable else "no sqli signals",
    }


def probe_sqli(target: str, path: str, param: str, payload: str) -> str:
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

    baseline_url = build_get_url(base, path, param, BASELINE)
    probe_url = build_get_url(base, path, param, payload)
    baseline = fetch_get(baseline_url)
    injected = fetch_get(probe_url)
    result = _analyze(baseline, injected, payload)

    lines = [
        "=== probe_sqli ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {payload}",
        f"status: {injected.get('status')}",
        f"vulnerable: {result['vulnerable']}",
        f"signals: {', '.join(result['signals']) or 'none'}",
        f"note: {result['note']}",
        f"url: {probe_url}",
    ]
    if result["vulnerable"]:
        lines.append(f"snippet: {injected.get('body', '')[:240]}")

    save_probe("probe_sqli", {
        "target": base,
        "path": path,
        "param": param,
        "payload": payload[:120],
        "vulnerable": result["vulnerable"],
        "signals": result["signals"],
        "contexts": result["signals"],
    })
    return "\n".join(lines)


def check_sqli(
    target: str,
    payload: str = "",
    path: str = "",
    param: str = "",
) -> str:
    base, err = web_base(target)
    if not base:
        return err

    use_payload = payload or DEFAULT_PROBE
    targets = []
    if path and param:
        targets = [(path.split("?", 1)[0], param)]
    else:
        for p in paths_to_probe(base):
            if "user" in p.lower() or p.endswith(".html"):
                targets.append((p.split("?", 1)[0], "id"))
        targets.append(("/user", "id"))

    seen = set()
    probes = []
    for tpath, tparam in targets:
        key = (tpath, tparam)
        if key in seen:
            continue
        seen.add(key)
        probes.append(probe_sqli(base, tpath, tparam, use_payload))

    vuln = [p for p in probes if "vulnerable: True" in p]
    lines = [
        "=== SQLi check ===",
        f"base: {base}",
        f"probes: {len(probes)}",
        f"payload: {use_payload}",
        "",
        f"LIKELY VULNERABLE: {len(vuln)}",
    ]
    for block in probes:
        if "vulnerable: True" in block:
            for line in block.splitlines():
                if line.startswith(("request:", "signals:", "url:")):
                    lines.append(f"  {line}")
    if not vuln:
        lines.append("  none found")
    return "\n".join(lines)
