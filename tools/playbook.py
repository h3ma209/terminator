"""Orchestration tools: playbook, auth, map, compare, findings."""

import json
import re
import urllib.error
import urllib.request

import config
from memory_store import (
    decode_jwt,
    load_findings,
    list_snapshots,
    now,
    resolve_snapshot,
    save_findings,
    save_snapshot,
)
from tools.analyze import analyze_target
from tools.api_routes import discover_api_paths, fetch_api_routes
from tools.http import (
    fetch_text,
    http_probe,
    parse_target,
    paths_to_probe,
    port_open,
    probe_path,
    request_method,
    score_probe,
    web_base,
)
from tools.profile import profile_target


def _collect_snapshot(base: str) -> dict:
    host, _ = parse_target(base)
    open_ports = []
    for port in sorted(config.COMMON_PORTS):
        if port_open(host, port):
            if port in config.HTTP_PROBE_PORTS:
                detail, _ = http_probe(host, port)
            else:
                detail = "tcp open"
            open_ports.append({"port": port, "detail": detail})
    header_req = urllib.request.Request(base + "/", headers={"User-Agent": "terminator"})
    missing_headers = list(config.HEADER_CHECKS)
    try:
        with urllib.request.urlopen(header_req, timeout=5) as res:
            headers = {k.lower(): v for k, v in res.headers.items()}
            missing_headers = [h for h in config.HEADER_CHECKS if h not in headers]
    except Exception:
        pass
    api_routes = []
    for path in discover_api_paths(base):
        get = request_method(base.rstrip("/") + path, "GET")
        post = request_method(base.rstrip("/") + path, "POST", b"{}")
        if {get.get("status"), post.get("status")} <= {404, "error"}:
            continue
        api_routes.append({"path": path, "get": get.get("status"), "post": post.get("status")})
    pages = []
    for path in paths_to_probe(base):
        probe = probe_path(base, path)
        if probe.get("status") != "error":
            pages.append({
                "path": path,
                "status": probe.get("status"),
                "has_form": probe.get("has_form"),
                "has_password": probe.get("has_password"),
            })
    ranked = []
    for page in pages:
        score, reasons = score_probe({
            "path": page["path"],
            "status": page["status"],
            "has_form": page.get("has_form"),
            "has_password": page.get("has_password"),
            "is_json": page["path"] in {"/health", "/api/profile"},
        })
        if score > 0:
            ranked.append((score, page, reasons))
    ranked.sort(key=lambda item: item[0], reverse=True)
    focus = [f"{p['path']}: {', '.join(r)}" for _, p, r in ranked[:6]]
    return {
        "timestamp": now(),
        "target": base,
        "open_ports": open_ports,
        "missing_headers": missing_headers,
        "api_routes": api_routes,
        "pages": pages,
        "focus": focus,
    }


def check_auth_flow(target: str, username: str = "demo", password: str = "demo") -> str:
    base, err = web_base(target)
    if not base:
        return err
    profile_url = base.rstrip("/") + "/api/profile"
    login_url = base.rstrip("/") + "/api/login"
    lines = [f"base: {base}", f"credentials: {username}/***", ""]
    anon = request_method(profile_url, "GET")
    lines.append(f"GET /api/profile (no token): {anon.get('status')} {anon.get('body', '')[:120]}")
    login_body = json.dumps({"username": username, "password": password}).encode()
    login = request_method(login_url, "POST", login_body)
    lines.append(f"POST /api/login: {login.get('status')} {login.get('body', '')[:200]}")
    token = None
    try:
        token = json.loads(login.get("body", "")).get("token")
    except json.JSONDecodeError:
        pass
    if not token:
        lines.append("result: login did not return a token")
        save_findings({**load_findings(), "target": base, "updated": now(), "auth": {"login": login.get("status"), "token": False}})
        return "\n".join(lines)
    payload = decode_jwt(token)
    lines.append(f"jwt payload: {json.dumps(payload)}")
    if payload and payload.get("exp"):
        from datetime import datetime, timezone
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        lines.append(f"jwt expires: {exp.isoformat()}")
    authed_req = urllib.request.Request(
        profile_url, headers={"User-Agent": "terminator", "Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(authed_req, timeout=5) as res:
            body = res.read(500).decode("utf-8", errors="replace")
            lines.append(f"GET /api/profile (with token): {res.status} {body[:200]}")
            auth_ok = res.status == 200
    except urllib.error.HTTPError as exc:
        body = exc.read(200).decode("utf-8", errors="replace")
        lines.append(f"GET /api/profile (with token): {exc.code} {body}")
        auth_ok = False
    notes = []
    if anon.get("status") in {401, 403}:
        notes.append("profile blocked without token")
    if auth_ok:
        notes.append("profile accessible with token")
    if payload and not payload.get("exp"):
        notes.append("jwt has no exp claim")
    lines.append("")
    lines.append("notes: " + ("; ".join(notes) if notes else "none"))
    save_findings({
        **load_findings(),
        "target": base,
        "updated": now(),
        "auth": {
            "anonymous_profile": anon.get("status"),
            "login": login.get("status"),
            "token_ok": auth_ok,
            "jwt_sub": (payload or {}).get("sub"),
            "jwt_exp": (payload or {}).get("exp"),
        },
    })
    return "\n".join(lines)


def map_site(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    todo = list(paths_to_probe(base))
    seen = set(todo)
    mapped = []
    while todo and len(mapped) < 25:
        path = todo.pop(0)
        url = base.rstrip("/") + path
        req = urllib.request.Request(url, headers={"User-Agent": "terminator"})
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                body = res.read(8000).decode("utf-8", errors="replace")
                status = res.status
        except urllib.error.HTTPError as exc:
            body = exc.read(1000).decode("utf-8", errors="replace") if exc.fp else ""
            status = exc.code
        except Exception as exc:
            mapped.append({"path": path, "status": "error", "error": str(exc)})
            continue
        links = set(re.findall(r'href=["\'](/[^"\']+)["\']', body, flags=re.I))
        externals = re.findall(r'href=["\'](https?://[^"\']+)["\']', body, flags=re.I)
        forms = len(re.findall(r"<form\b", body, flags=re.I))
        mapped.append({
            "path": path,
            "status": status,
            "links": len(links),
            "external_links": len(externals),
            "forms": forms,
        })
        for link in links:
            if link not in seen and not link.startswith("/api"):
                seen.add(link)
                todo.append(link)
    lines = [f"base: {base}", f"pages mapped: {len(mapped)}", ""]
    for page in mapped:
        bits = [f"{page['path']} -> {page['status']}"]
        if page.get("forms"):
            bits.append(f"forms={page['forms']}")
        if page.get("links"):
            bits.append(f"links={page['links']}")
        if page.get("external_links"):
            bits.append(f"external={page['external_links']}")
        lines.append("  " + " | ".join(bits))
    save_findings({**load_findings(), "target": base, "updated": now(), "site_map": mapped})
    return "\n".join(lines)


def compare_runs(snapshot_a: str = "", snapshot_b: str = "") -> str:
    snaps = list_snapshots()
    if not snaps:
        return "error: no snapshots in reports/"
    path_a = resolve_snapshot(snapshot_a) if snapshot_a else (snaps[-2] if len(snaps) > 1 else None)
    path_b = resolve_snapshot(snapshot_b) if snapshot_b else snaps[-1]
    if not path_a or not path_b:
        return "error: need at least two snapshots. run playbook first."
    a = json.loads(path_a.read_text(encoding="utf-8"))
    b = json.loads(path_b.read_text(encoding="utf-8"))
    lines = [f"A: {path_a.name}", f"B: {path_b.name}", ""]

    def port_set(data):
        return {item["port"] for item in data.get("open_ports", [])}

    pa, pb = port_set(a), port_set(b)
    if pa != pb:
        lines.append(f"ports added: {sorted(pb - pa) or 'none'}")
        lines.append(f"ports removed: {sorted(pa - pb) or 'none'}")
    ha, hb = set(a.get("missing_headers", [])), set(b.get("missing_headers", []))
    if ha != hb:
        lines.append(f"headers now present: {sorted(ha - hb) or 'none'}")
        lines.append(f"headers now missing: {sorted(hb - ha) or 'none'}")
    ra = {r["path"] for r in a.get("api_routes", [])}
    rb = {r["path"] for r in b.get("api_routes", [])}
    if ra != rb:
        lines.append(f"api routes added: {sorted(rb - ra) or 'none'}")
        lines.append(f"api routes removed: {sorted(ra - rb) or 'none'}")
    if a.get("auth") != b.get("auth"):
        lines.append(f"auth A: {json.dumps(a.get('auth', {}))}")
        lines.append(f"auth B: {json.dumps(b.get('auth', {}))}")
    if a.get("focus") != b.get("focus"):
        lines.append("focus order changed")
        lines.append(f"  A: {a.get('focus', [])}")
        lines.append(f"  B: {b.get('focus', [])}")
    if len(lines) == 3:
        lines.append("no differences found")
    return "\n".join(lines)


def show_findings() -> str:
    data = load_findings()
    if not data:
        return "no findings saved yet. run playbook or check_auth_flow first."
    snaps = list_snapshots()
    lines = ["=== session findings ===", json.dumps(data, indent=2)]
    if snaps:
        lines.append("")
        lines.append("snapshots:")
        for snap in snaps[-5:]:
            lines.append(f"  {snap.name}")
    return "\n".join(lines)


def run_playbook(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    sections = [
        ("profile", profile_target(base)),
        ("api routes", fetch_api_routes(base)),
        ("auth flow", check_auth_flow(base)),
        ("site map", map_site(base)),
        ("analysis", analyze_target(base)),
    ]
    snapshot = _collect_snapshot(base)
    snapshot["auth"] = load_findings().get("auth", {})
    snap_path = save_snapshot(snapshot)
    save_findings({
        **load_findings(),
        "target": base,
        "updated": now(),
        "last_snapshot": str(snap_path),
        "open_ports": snapshot["open_ports"],
        "missing_headers": snapshot["missing_headers"],
        "api_routes": snapshot["api_routes"],
        "focus": snapshot["focus"],
    })
    lines = [f"playbook: {base}", f"snapshot: {snap_path}", f"findings: {config.FINDINGS_PATH}", ""]
    for title, body in sections:
        lines.append(f"=== {title} ===")
        lines.append(body)
        lines.append("")
    return "\n".join(lines).strip()
