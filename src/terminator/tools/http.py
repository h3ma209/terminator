"""Low-level HTTP and localhost network helpers."""

import re
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

import config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"redirect blocked: {newurl}")


def localhost_only(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def parse_target(target: str) -> tuple[str, int | None]:
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("invalid url")
        return parsed.hostname, parsed.port
    if ":" in target and target.rsplit(":", 1)[-1].isdigit():
        host, port = target.rsplit(":", 1)
        return host.strip("[]"), int(port)
    return target, None


def port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def fetch_text(url: str, max_len: int = 1200) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read(max_len).decode("utf-8", errors="replace").strip()
            return f"status {res.status}\n{body}"
    except Exception as exc:
        return f"error: {exc}"


def request_method(url: str, method: str, body: bytes | None = None) -> dict:
    headers = {"User-Agent": "terminator"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            raw = res.read(800).decode("utf-8", errors="replace")
            return {
                "status": res.status,
                "content_type": res.headers.get("Content-Type", ""),
                "allow": res.headers.get("Allow", ""),
                "body": raw.strip()[:300],
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read(800).decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "status": exc.code,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "allow": exc.headers.get("Allow", "") if exc.headers else "",
            "body": raw.strip()[:300],
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def http_probe(host: str, port: int) -> tuple[str, str | None]:
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
        try:
            with urllib.request.urlopen(req, timeout=3) as res:
                body = res.read(2000).decode("utf-8", errors="replace")
                title = re.search(r"<title[^>]*>([^<]+)", body, flags=re.I)
                server = res.headers.get("Server")
                ctype = res.headers.get("Content-Type")
                name = title.group(1).strip() if title else "no title"
                parts = [f"{scheme} {res.status}", f"title={name}"]
                parts.append(f"server={server}" if server else "server=(not sent)")
                if ctype:
                    parts.append(f"content-type={ctype}")
                return " ".join(parts), url
        except Exception:
            continue
    return "open tcp, no http response", None


def web_base(target: str) -> tuple[str, str] | tuple[None, str]:
    try:
        host, hint_port = parse_target(target)
    except ValueError as exc:
        return None, f"error: {exc}"
    if not localhost_only(host):
        return None, "blocked: only works on 127.0.0.1 or localhost"
    if hint_port and port_open(host, hint_port):
        return f"http://{host}:{hint_port}", ""
    for port in (3000, 8080, 80, 8000, 5000):
        if port_open(host, port):
            return f"http://{host}:{port}", ""
    return None, f"error: no common web port open on {host}"


def header_report(url: str) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            headers = {k.lower(): v for k, v in res.headers.items()}
    except Exception as exc:
        return f"error: {exc}"
    lines = ["security headers:"]
    for name in config.HEADER_CHECKS:
        if name in headers:
            lines.append(f"  present {name}: {headers[name]}")
        else:
            lines.append(f"  missing {name}")
    for key in ("server", "x-powered-by"):
        if key in headers:
            lines.append(f"  {key}: {headers[key]}")
    return "\n".join(lines)


def cookie_notes(headers: dict) -> list:
    raw = headers.get("set-cookie")
    if not raw:
        return ["no set-cookie header"]
    notes = []
    for part in raw.split(","):
        lowered = part.lower()
        if "expires=" in lowered or "max-age=" in lowered or "=" not in part:
            continue
        flags = []
        if "httponly" not in lowered:
            flags.append("missing httponly")
        if "secure" not in lowered:
            flags.append("missing secure")
        if "samesite" not in lowered:
            flags.append("missing samesite")
        name = part.split("=", 1)[0].strip()
        notes.append(f"{name}: {', '.join(flags) if flags else 'flags present'}")
    return notes or ["set-cookie present"]


def tls_note(hostname: str, port: int) -> str:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
    except Exception as exc:
        return f"tls error: {exc}"
    not_after = cert.get("notAfter")
    if not not_after:
        return "tls certificate present, expiry not shown"
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expiry - datetime.now(timezone.utc)).days
    return f"tls certificate expires in {days} days ({not_after})"


def page_notes(body: str, page_url: str) -> list:
    notes = []
    scripts = re.findall(r"<script\b[^>]*src=[\"']([^\"']+)", body, flags=re.I)
    inline = len(re.findall(r"<script\b(?![^>]*\bsrc=)", body, flags=re.I))
    notes.append(f"external scripts: {len(scripts)}")
    notes.append(f"inline scripts: {inline}")
    forms = re.findall(r"<form\b([^>]*)>", body, flags=re.I)
    notes.append(f"forms: {len(forms)}")
    if re.search(r"type=[\"']password[\"']", body, flags=re.I):
        notes.append("page contains a password field")
    for attrs in forms:
        action = re.search(r"action=[\"']([^\"']*)", attrs, flags=re.I)
        if action and action.group(1).lower().startswith("http://"):
            notes.append(f"form action uses http: {action.group(1)}")
    if page_url.lower().startswith("https://") and re.search(r"(src|href)=[\"']http://", body, flags=re.I):
        notes.append("https page links to an http resource")
    return notes


def paths_to_probe(base: str) -> list[str]:
    paths = {
        "/", "/health", "/profile.html", "/search.html", "/search",
        "/user", "/redirect", "/files", "/fetch", "/ping", "/render", "/echo",
        "/api/login", "/api/profile", "/api/admin", "/api/cors", "/robots.txt",
    }
    sitemap = fetch_text(base + "/sitemap.xml", 1200)
    for match in re.finditer(r"<loc>https?://[^/]+(/[^<]*)</loc>", sitemap, flags=re.I):
        paths.add(match.group(1))
    return sorted(paths)


def probe_path(base: str, path: str) -> dict:
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read(3000).decode("utf-8", errors="replace")
            ctype = (res.headers.get("Content-Type") or "").lower()
            return {
                "url": url,
                "path": path,
                "status": res.status,
                "content_type": ctype,
                "has_form": "<form" in body.lower(),
                "has_password": bool(re.search(r'type=["\']password["\']', body, flags=re.I)),
                "is_json": "application/json" in ctype or body.lstrip().startswith("{"),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(500).decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "url": url,
            "path": path,
            "status": exc.code,
            "content_type": "",
            "has_form": False,
            "has_password": False,
            "is_json": body.lstrip().startswith("{"),
        }
    except Exception as exc:
        return {"url": url, "path": path, "status": "error", "error": str(exc)}


def score_probe(probe: dict) -> tuple[int, list[str]]:
    if probe.get("status") == "error":
        return 0, ["unreachable"]
    score = 0
    reasons = []
    path = probe.get("path") or ""
    status = probe.get("status")
    if path.startswith("/api"):
        score += 80
        reasons.append("API route")
    if path in {"/profile.html"}:
        score += 65
        reasons.append("user profile page")
    if path in {"/search", "/search.html"} or "search" in path.lower():
        score += 70
        reasons.append("search/input reflection surface")
    if probe.get("has_password"):
        score += 75
        reasons.append("password field")
    if probe.get("has_form"):
        score += 45
        reasons.append("HTML form")
    if probe.get("is_json"):
        score += 50
        reasons.append("JSON response")
    if status in {401, 403}:
        score += 70
        reasons.append("auth gate")
    if status == 405:
        score += 60
        reasons.append("method restricted")
    if status == 200 and path.startswith("/api"):
        score += 55
        reasons.append("API reachable")
    if path == "/health":
        score += 25
        reasons.append("health/info endpoint")
    if path in {"/about.html", "/contact.html", "/privacy.html", "/terms.html"}:
        score -= 20
        reasons.append("static page")
    return score, reasons
