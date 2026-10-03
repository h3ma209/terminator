"""Network probes: CORS, SSRF, CRLF."""

import re
import urllib.request

from terminator.tools.http import web_base
from terminator.tools.probe_http import build_get_url, fetch_get, save_probe
from terminator.catalog import all_payloads, check_with_variations, default_payload

EVIL_ORIGIN = "https://evil.example"


def probe_cors(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/api/cors"
    origin = payload or EVIL_ORIGIN
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "terminator", "Origin": origin})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            headers = {k.lower(): v for k, v in res.headers.items()}
            body = res.read(500).decode("utf-8", errors="replace")
            status = res.status
    except Exception as exc:
        return f"error: {exc}"

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    signals = []
    if acao == "*" or acao == origin:
        signals.append(f"Access-Control-Allow-Origin: {acao}")
    if acac.lower() == "true" and acao == origin:
        signals.append("credentials allowed with reflected origin")
    vulnerable = bool(signals)

    lines = [
        "=== probe_cors ===",
        f"target: {base}",
        f"GET {path} Origin: {origin}",
        f"status: {status}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"body: {body[:160]}",
    ]
    save_probe("probe_cors", {
        "target": base, "path": path, "param": "Origin",
        "payload": origin, "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_cors(target: str) -> str:
    base, err = web_base(target)
    if err:
        return err
    probes = []
    for pl in all_payloads("cors"):
        probes.append(probe_cors(base, pl, "/api/cors", "Origin"))
        if "vulnerable: True" in probes[-1]:
            break
    vuln = [p for p in probes if "vulnerable: True" in p]
    lines = ["=== CORS check ===", f"target: {base}", f"styles tried: {len(all_payloads('cors'))}", ""]
    if vuln:
        lines.append("LIKELY VULNERABLE:")
        lines.extend(f"  {l}" for l in vuln[0].splitlines() if l.startswith(("GET", "vulnerable:", "signals:")))
    else:
        lines.append("LIKELY VULNERABLE: none")
    return "\n".join(lines)


def probe_ssrf(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/fetch"
    param = param or "url"
    probe_url = payload or "http://127.0.0.1:11434/"
    url = build_get_url(base, path, param, probe_url)
    injected = fetch_get(url)
    body = injected.get("body") or ""
    signals = []
    if injected.get("status") == 200 and "fetched" in body:
        signals.append("server fetched attacker URL")
    if "ollama" in body.lower() or "11434" in body:
        signals.append("internal service response in body")
    if probe_url in body:
        signals.append("target URL echoed")
    vulnerable = bool(signals)

    lines = [
        "=== probe_ssrf ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {probe_url}",
        f"status: {injected.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"url: {url}",
    ]
    save_probe("probe_ssrf", {
        "target": base, "path": path, "param": param,
        "payload": probe_url[:120], "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_ssrf(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    return check_with_variations(
        "ssrf", "SSRF check", probe_ssrf,
        target, path or "/fetch", param or "url", payload,
    )


def probe_crlf(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/echo"
    param = param or "msg"
    probe_val = payload or "test%0d%0AX-Injected: evil"
    url = build_get_url(base, path, param, probe_val)
    injected = fetch_get(url)
    headers = injected.get("headers") or {}
    signals = []
    if headers.get("x-injected"):
        signals.append("injected header reflected")
    if "evil" in str(headers).lower():
        signals.append("crlf smuggled into response headers")
    body = injected.get("body") or ""
    if "%0d%0a" in probe_val and "evil" in body:
        signals.append("crlf sequence in response")
    vulnerable = bool(signals)

    lines = [
        "=== probe_crlf ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {probe_val}",
        f"status: {injected.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"headers: {headers}",
    ]
    save_probe("probe_crlf", {
        "target": base, "path": path, "param": param,
        "payload": probe_val[:120], "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_crlf(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    return check_with_variations(
        "crlf", "CRLF check", probe_crlf,
        target, path or "/echo", param or "msg", payload,
    )
