"""Reflected XSS detection for localhost targets."""

import re
import urllib.error
import urllib.request
from urllib.parse import urlencode

from memory_store import load_findings, now, save_findings
from tools.http import paths_to_probe, web_base

CANARY = "terminatorCANARY7x2"
XSS_PROBE = "terminator<xsstest7x2>"
MAX_PAYLOAD_LEN = 500
COMMON_PARAMS = ("q", "query", "search", "s", "term", "keyword", "id", "name", "page", "msg", "message")


def _fetch(url: str, max_len: int = 16000) -> tuple[int | str, str]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            body = res.read(max_len).decode("utf-8", errors="replace")
            return res.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(max_len).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except Exception as exc:
        return "error", str(exc)


def _form_get_params(html: str) -> list[tuple[str, str]]:
    params = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.I | re.S):
        attrs, inner = match.group(1), match.group(2)
        method = re.search(r'method=[\"\']([^\"\']+)', attrs, flags=re.I)
        if method and method.group(1).strip().lower() not in {"", "get"}:
            continue
        action = re.search(r'action=[\"\']([^\"\']*)', attrs, flags=re.I)
        action_path = action.group(1).split("?", 1)[0] if action else ""
        for inp in re.finditer(r"<input\b([^>]*)/?>", inner, flags=re.I):
            tag = inp.group(1)
            itype = re.search(r'type=[\"\']([^\"\']+)', tag, flags=re.I)
            if itype and itype.group(1).lower() in {"submit", "button", "hidden", "image", "file"}:
                continue
            name = re.search(r'name=[\"\']([^\"\']+)', tag, flags=re.I)
            if name:
                params.append((action_path or "", name.group(1)))
    return params


def _discover_targets(base: str, only_path: str = "", only_param: str = "") -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    targets: list[tuple[str, str]] = []

    def add(path: str, param: str) -> None:
        path = path.split("?", 1)[0] or "/"
        if not path.startswith("/"):
            path = "/" + path
        if only_path and path != only_path.split("?", 1)[0]:
            return
        if only_param and param != only_param:
            return
        key = (path, param)
        if key not in seen:
            seen.add(key)
            targets.append(key)

    if only_path and only_param:
        add(only_path, only_param)
        return targets

    for path in paths_to_probe(base):
        if "search" in path.lower():
            add(path.split("?", 1)[0], "q")
        status, body = _fetch(base.rstrip("/") + path)
        if status == "error" or not isinstance(status, int):
            continue
        for action_path, param in _form_get_params(body):
            add(action_path or path.split("?", 1)[0], param)

    add("/search", "q")
    if not only_path:
        for path in paths_to_probe(base):
            if path.endswith(".html") or path == "/":
                for param in COMMON_PARAMS:
                    add(path.split("?", 1)[0], param)

    return targets


def _contexts(body: str, probe: str) -> list[str]:
    contexts = []
    if probe in body:
        contexts.append("html body")
    esc = probe.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
    if esc in body and probe not in body:
        contexts.append("html-encoded")
    if re.search(rf'value=[\"\']{re.escape(probe)}[\"\']', body, flags=re.I):
        contexts.append("attribute value")
    if re.search(rf">{re.escape(probe)}<", body):
        contexts.append("between tags")
    return contexts


def _analyze_reflection(status: int | str, body: str, payload: str) -> dict:
    reflected = isinstance(body, str) and payload in body
    encoded = (
        isinstance(body, str)
        and not reflected
        and payload.replace("<", "&lt;").replace(">", "&gt;") in body
    )
    contexts = _contexts(body, payload) if reflected else (["html-encoded"] if encoded else [])
    vulnerable = reflected and bool(contexts) and "html-encoded" not in contexts
    note = ""
    if status == "error":
        note = str(body)
    elif vulnerable:
        note = "payload reflected unescaped"
    elif encoded:
        note = "reflected but encoded (likely safe)"
    elif reflected:
        note = "reflected (review context)"
    else:
        note = "payload not reflected"
    return {
        "status": status,
        "reflected": reflected or encoded,
        "vulnerable": vulnerable,
        "contexts": contexts,
        "note": note,
    }


def probe_xss(target: str, path: str, param: str, payload: str) -> str:
    """Single-shot XSS probe with model-crafted payload."""
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
    url = base.rstrip("/") + path + "?" + urlencode({param: payload})
    status, body = _fetch(url)
    result = _analyze_reflection(status, body, payload)

    lines = [
        "=== probe_xss ===",
        f"target: {base}",
        f"request: GET {path}?{param}=...",
        f"payload: {payload}",
        f"status: {status}",
        f"reflected: {result['reflected']}",
        f"vulnerable: {result['vulnerable']}",
        f"context: {', '.join(result['contexts']) or 'none'}",
        f"note: {result['note']}",
        f"url: {url}",
    ]
    if result["vulnerable"]:
        snippet_start = body.find(payload)
        if snippet_start >= 0:
            start = max(0, snippet_start - 40)
            end = min(len(body), snippet_start + len(payload) + 40)
            lines.append(f"snippet: ...{body[start:end]}...")

    save_findings({
        **load_findings(),
        "target": base,
        "updated": now(),
        "last_probe": {
            "skill": "probe_xss",
            "path": path,
            "param": param,
            "payload": payload[:120],
            "vulnerable": result["vulnerable"],
            "contexts": result["contexts"],
        },
    })
    return "\n".join(lines)


def probe_reflection(
    base: str,
    path: str,
    param: str,
    payload: str = "",
    canary: str = "",
) -> dict:
    url_base = base.rstrip("/") + path
    result = {
        "path": path,
        "param": param,
        "payload": payload or XSS_PROBE,
        "url": "",
        "status": 0,
        "reflected": False,
        "vulnerable": False,
        "contexts": [],
        "note": "",
    }

    if payload:
        xss_url = url_base + "?" + urlencode({param: payload})
        status, xss_body = _fetch(xss_url)
        result.update(_analyze_reflection(status, xss_body, payload))
        result["url"] = xss_url
        result["payload"] = payload
        return result

    use_canary = canary or CANARY
    canary_url = url_base + "?" + urlencode({param: use_canary})
    status, body = _fetch(canary_url)
    result["url"] = canary_url
    result["status"] = status
    if status == "error":
        result["note"] = body
        return result
    if use_canary not in body:
        result["note"] = "param not reflected"
        return result

    xss_url = url_base + "?" + urlencode({param: XSS_PROBE})
    _, xss_body = _fetch(xss_url)
    analysis = _analyze_reflection(status, xss_body, XSS_PROBE)
    result.update(analysis)
    result["url"] = xss_url
    result["payload"] = XSS_PROBE
    return result


def check_xss(
    target: str,
    payload: str = "",
    payloads: list | None = None,
    path: str = "",
    param: str = "",
) -> str:
    base, err = web_base(target)
    if not base:
        return err

    custom = [p for p in ([payload] if payload else []) + (payloads or []) if p]
    for p in custom:
        if len(p) > MAX_PAYLOAD_LEN:
            return f"error: payload too long (max {MAX_PAYLOAD_LEN})"

    targets = _discover_targets(base, only_path=path, only_param=param)
    if path and param and not targets:
        targets = [(path.split("?", 1)[0] if path.startswith("/") else "/" + path, param)]

    probe_list = custom or [XSS_PROBE]
    probes = []
    for tpath, tparam in targets:
        for pl in probe_list:
            probes.append(probe_reflection(base, tpath, tparam, payload=pl))

    vuln = [p for p in probes if p.get("vulnerable")]
    encoded = [p for p in probes if p.get("reflected") and not p.get("vulnerable") and "encoded" in p.get("note", "")]
    reflected_safe = [p for p in probes if p.get("reflected") and not p.get("vulnerable") and p not in encoded]
    quiet = [p for p in probes if not p.get("reflected") and p.get("status") != "error"]

    lines = [
        "=== XSS check ===",
        f"base: {base}",
        f"probes: {len(probes)}",
    ]
    if custom:
        lines.append(f"custom payload(s): {len(custom)}")
    if path or param:
        lines.append(f"scope: path={path or '*'} param={param or '*'}")
    lines.append("")

    if vuln:
        lines.append("LIKELY VULNERABLE (reflected, unescaped):")
        for p in vuln:
            ctx = ", ".join(p.get("contexts") or ["unknown"])
            pl = p.get("payload", XSS_PROBE)
            lines.append(f"  GET {p['path']}?{p['param']}=...")
            lines.append(f"    payload: {pl[:80]}")
            lines.append(f"    status: {p['status']} | context: {ctx}")
            lines.append(f"    test: {p['url']}")
    else:
        lines.append("LIKELY VULNERABLE: none found")

    lines.append("")
    if encoded:
        lines.append("REFLECTED BUT ENCODED (likely safe):")
        for p in encoded:
            lines.append(f"  {p['path']}?{p['param']}= — {p['note']}")
    else:
        lines.append("REFLECTED BUT ENCODED: none")

    lines.append("")
    if reflected_safe:
        lines.append("REFLECTED (inconclusive):")
        for p in reflected_safe[:5]:
            lines.append(f"  {p['path']}?{p['param']}= — {p['note']}")
        if len(reflected_safe) > 5:
            lines.append(f"  ... and {len(reflected_safe) - 5} more")

    lines.append("")
    lines.append(f"no reflection: {len(quiet)} param(s)")

    save_findings({
        **load_findings(),
        "target": base,
        "updated": now(),
        "xss": {
            "vulnerable": [
                {
                    "path": p["path"],
                    "param": p["param"],
                    "payload": (p.get("payload") or "")[:120],
                    "contexts": p.get("contexts", []),
                }
                for p in vuln
            ],
            "encoded": len(encoded),
            "probes": len(probes),
            "custom_payloads": custom,
        },
    })
    return "\n".join(lines)
