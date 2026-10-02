"""Local tool-calling agent for Ollama (qwen2.5-coder)."""

import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
MAX_STEPS = 8
MAX_READ = 32_000
MEMORY_TURNS = 12
MEMORY_CHARS = 400
CONTEXT_TURNS = 6
TOOL_OUTPUT_MAX = 1800
FETCH_BODY_MAX = 500
FILE_HEAD_LINES = 60

ROOT = Path.cwd().resolve()
AGENT_DIR = Path(__file__).resolve().parent
MEMORY_PATH = AGENT_DIR / "memory.jsonl"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and folders under a directory inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory relative to the workspace. Use . for the workspace root.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to the workspace.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "GET an http or https URL and return status plus body text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL, http or https.",
                    }
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_local",
            "description": "Passive header check of a localhost URL. One normal GET. No attack payloads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Example: http://127.0.0.1:3000/",
                    }
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_url",
            "description": "Passive review of one http or https URL: status, security headers, cookie flags, TLS expiry, forms, and script tags. One normal GET. No attack payloads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL to inspect.",
                    }
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "profile_target",
            "description": "Full localhost profile: ports, HTTP banners, security headers, robots.txt, and sitemap. No attack payloads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host, IP, or URL. Example: 127.0.0.1 or http://127.0.0.1:3000",
                    }
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_target",
            "description": "Merge profile, page inspect, and endpoint probes. Rank where to focus review next. Passive only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host or URL. Example: http://127.0.0.1:3000",
                    }
                },
                "required": ["target"],
            },
        },
    },
]


def inside(path: Path) -> Path:
    full = (ROOT / path).resolve()
    if not full.is_relative_to(ROOT):
        raise ValueError("path escapes workspace")
    return full


SKIP = {"__pycache__", ".git", ".venv", "venv"}


def list_dir(path: str) -> str:
    folder = inside(Path(path))
    if not folder.is_dir():
        return f"not a directory: {path}"
    names = sorted(
        p.name + ("/" if p.is_dir() else "")
        for p in folder.iterdir()
        if p.name not in SKIP
    )
    return "\n".join(names) if names else "(empty)"


def read_file(path: str) -> str:
    file = inside(Path(path))
    if not file.is_file():
        return f"not a file: {path}"
    text = file.read_text(encoding="utf-8", errors="replace")
    if len(text) > MAX_READ:
        return text[:MAX_READ] + "\n...[truncated]"
    return text


def fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "blocked: url must be http or https"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read(MAX_READ).decode("utf-8", errors="replace")
            return f"status {res.status}\n{body}"
    except Exception as exc:
        return f"error: {exc}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"redirect blocked: {newurl}")


_HEADER_CHECKS = (
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy",
    "x-frame-options",
    "strict-transport-security",
    "permissions-policy",
)


def _cookie_notes(headers: dict) -> list:
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


def _tls_note(hostname: str, port: int) -> str:
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


def _page_notes(body: str, page_url: str) -> list:
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


def scan_local(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        return "blocked: only http://127.0.0.1 or http://localhost"
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=10) as res:
            body = res.read(4000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in res.headers.items()}
            status = res.status
    except Exception as exc:
        return f"error: {exc}"
    lines = [f"url: {url}", f"status: {status}", "headers:"]
    for key in sorted(headers):
        lines.append(f"  {key}: {headers[key]}")
    lines.append("passive findings:")
    for name in _HEADER_CHECKS:
        if name not in headers:
            lines.append(f"  missing {name}")
    if "server" in headers:
        lines.append("  server header discloses software")
    if "<script" in body.lower():
        lines.append("  page contains a script tag")
    else:
        lines.append("  no script tag in the first 4000 bytes")
    return "\n".join(lines)


def inspect_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "blocked: url must be http or https"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read(MAX_READ).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in res.headers.items()}
            status = res.status
            final = res.geturl()
    except Exception as exc:
        return f"error: {exc}"
    lines = [f"requested: {url}", f"final: {final}", f"status: {status}"]
    if parsed.scheme == "http":
        lines.append("page is served over http")
    lines.append("headers missing:")
    missing = [name for name in _HEADER_CHECKS if name not in headers]
    lines.extend(f"  {name}" for name in missing)
    if not missing:
        lines.append("  none from the checklist")
    if "server" in headers or "x-powered-by" in headers:
        lines.append("response identifies server software")
    lines.append("cookies:")
    lines.extend(f"  {note}" for note in _cookie_notes(headers))
    if parsed.scheme == "https":
        port = parsed.port or 443
        lines.append(_tls_note(parsed.hostname, port))
    lines.append("page:")
    lines.extend(f"  {note}" for note in _page_notes(body, final))
    return "\n".join(lines)


_COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    80: "http",
    443: "https",
    3000: "http-dev",
    3306: "mysql",
    5000: "dev",
    5432: "postgres",
    6379: "redis",
    8000: "dev",
    8080: "http-alt",
    11434: "ollama",
    27017: "mongodb",
}


def _localhost_only(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _parse_target(target: str) -> tuple[str, int | None]:
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


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_probe(host: str, port: int) -> tuple[str, str | None]:
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
                if server:
                    parts.append(f"server={server}")
                else:
                    parts.append("server=(not sent)")
                if ctype:
                    parts.append(f"content-type={ctype}")
                return " ".join(parts), url
        except Exception:
            continue
    return "open tcp, no http response", None


def _fetch_text(url: str, max_len: int = 1200) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read(max_len).decode("utf-8", errors="replace").strip()
            return f"status {res.status}\n{body}"
    except Exception as exc:
        return f"error: {exc}"


def _header_report(url: str) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            headers = {k.lower(): v for k, v in res.headers.items()}
    except Exception as exc:
        return f"error: {exc}"
    lines = ["security headers:"]
    for name in _HEADER_CHECKS:
        if name in headers:
            lines.append(f"  present {name}: {headers[name]}")
        else:
            lines.append(f"  missing {name}")
    for key in ("server", "x-powered-by"):
        if key in headers:
            lines.append(f"  {key}: {headers[key]}")
    return "\n".join(lines)


def profile_target(target: str) -> str:
    try:
        host, hint_port = _parse_target(target)
    except ValueError as exc:
        return f"error: {exc}"
    if not _localhost_only(host):
        return "blocked: profile_target only works on 127.0.0.1 or localhost"
    try:
        resolved = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
    except OSError as exc:
        return f"error: cannot resolve {host}: {exc}"
    ports = set(_COMMON_PORTS)
    if hint_port:
        ports.add(hint_port)
    lines = [
        f"target: {target}",
        f"host: {host}",
        f"resolved: {resolved}",
        "open ports:",
    ]
    open_ports = []
    web_base = None
    if hint_port and _port_open(host, hint_port):
        web_base = f"http://{host}:{hint_port}"
    for port in sorted(ports):
        if _port_open(host, port):
            label = _COMMON_PORTS.get(port, "unknown")
            if port in {80, 443, 3000, 5000, 8000, 8080, 11434}:
                detail, base = _http_probe(host, port)
                if base and not web_base:
                    web_base = base.rstrip("/")
            else:
                detail, base = "tcp open", None
            open_ports.append((port, label, detail))
            lines.append(f"  {port}/{label}: {detail}")
    if not open_ports:
        lines.append("  none from the common port list")
    lines.append(f"scanned {len(ports)} common ports with short tcp connect probes")
    if web_base:
        lines.append("")
        lines.append(_header_report(web_base + "/"))
        lines.append("")
        lines.append("robots.txt:")
        lines.append(_fetch_text(web_base + "/robots.txt", 800))
        lines.append("")
        lines.append("sitemap.xml:")
        lines.append(_fetch_text(web_base + "/sitemap.xml", 800))
    return "\n".join(lines)


def _web_base(target: str) -> tuple[str, str] | tuple[None, str]:
    try:
        host, hint_port = _parse_target(target)
    except ValueError as exc:
        return None, f"error: {exc}"
    if not _localhost_only(host):
        return None, "blocked: analyze_target only works on 127.0.0.1 or localhost"
    if hint_port and _port_open(host, hint_port):
        return f"http://{host}:{hint_port}", ""
    for port in (3000, 8080, 80, 8000, 5000):
        if _port_open(host, port):
            return f"http://{host}:{port}", ""
    return None, f"error: no common web port open on {host}"


def _paths_to_probe(base: str) -> list[str]:
    paths = {"/", "/health", "/profile.html", "/api/login", "/api/profile", "/robots.txt"}
    sitemap = _fetch_text(base + "/sitemap.xml", 1200)
    for match in re.finditer(r"<loc>https?://[^/]+(/[^<]*)</loc>", sitemap, flags=re.I):
        paths.add(match.group(1))
    return sorted(paths)


def _probe_path(base: str, path: str) -> dict:
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


def _score_probe(probe: dict) -> tuple[int, list[str]]:
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


def analyze_target(target: str) -> str:
    base, err = _web_base(target)
    if not base:
        return err
    profile = profile_target(base)
    inspect = inspect_url(base + "/")
    probes = [_probe_path(base, path) for path in _paths_to_probe(base)]
    ranked = []
    for probe in probes:
        score, reasons = _score_probe(probe)
        if score > 0:
            ranked.append((score, probe, reasons))
    ranked.sort(key=lambda item: item[0], reverse=True)
    robots = _fetch_text(base + "/robots.txt", 400)
    lines = [
        "=== merged intel ===",
        profile,
        "",
        "=== page inspect (home) ===",
        inspect,
        "",
        "=== endpoint probes ===",
    ]
    for probe in probes:
        status = probe.get("status")
        bits = [f"{probe['path']} -> {status}"]
        if probe.get("content_type"):
            bits.append(probe["content_type"])
        if probe.get("has_password"):
            bits.append("password field")
        if probe.get("is_json"):
            bits.append("json")
        lines.append("  " + " | ".join(bits))
    lines.append("")
    lines.append("=== recommended focus (priority order) ===")
    if "Disallow: /api/" in robots:
        lines.append("  note: robots.txt hides /api/ — review API auth first")
    if ranked:
        for idx, (score, probe, reasons) in enumerate(ranked[:8], start=1):
            label = ", ".join(reasons)
            lines.append(f"  {idx}. [{score}] {probe['url']} — {label}")
    else:
        lines.append("  no high-value endpoints found from probes")
    lines.append("")
    lines.append("=== lower priority / skip for now ===")
    low = [p for p in probes if _score_probe(p)[0] <= 25]
    if low:
        for probe in low:
            lines.append(f"  {probe['path']} (status {probe.get('status')})")
    else:
        lines.append("  none")
    return "\n".join(lines)


HANDLERS = {
    "list_dir": list_dir,
    "read_file": read_file,
    "fetch_url": fetch_url,
    "scan_local": scan_local,
    "inspect_url": inspect_url,
    "profile_target": profile_target,
    "analyze_target": analyze_target,
}


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", html)
    text = re.sub(r"(?is)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def _summarize_fetch(content: str) -> str:
    lines = content.splitlines()
    if not lines or not lines[0].startswith("status "):
        return content
    status = lines[0]
    body = "\n".join(lines[1:])
    title = re.search(r"(?is)<title[^>]*>([^<]+)", body)
    title_bit = f" title={title.group(1).strip()}" if title else ""
    if "<html" in body.lower() or "<!doctype" in body.lower():
        plain = _strip_html(body)[:FETCH_BODY_MAX]
        return f"{status}{title_bit}\ntext: {plain or '(empty)'}"
    return f"{status}\n{body[:FETCH_BODY_MAX]}"


def clean_text(text: str, limit: int = TOOL_OUTPUT_MAX) -> str:
    if not text:
        return ""
    text = text.replace("\x00", "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if "\n" in cut[-300:]:
        cut = cut[: cut.rfind("\n")]
    return cut.rstrip() + "\n...[truncated]"


def clean_tool_output(tool: str, content: str) -> str:
    if tool == "fetch_url":
        return clean_text(_summarize_fetch(content), TOOL_OUTPUT_MAX)
    if tool in {"profile_target", "analyze_target"}:
        return clean_text(content, TOOL_OUTPUT_MAX * 2)
    if tool == "read_file" and content.count("\n") > FILE_HEAD_LINES:
        lines = content.splitlines()
        head = "\n".join(lines[:FILE_HEAD_LINES])
        return clean_text(f"{head}\n...[file truncated, {len(lines)} lines total]", TOOL_OUTPUT_MAX)
    return clean_text(content, TOOL_OUTPUT_MAX)


def prepare_messages(messages: list) -> list:
    if not messages:
        return []
    system = [messages[0]] if messages and messages[0].get("role") == "system" else []
    rest = messages[len(system):]
    kept = []
    users = 0
    for msg in reversed(rest):
        kept.append(msg)
        if msg.get("role") == "user":
            users += 1
            if users > CONTEXT_TURNS:
                break
    kept.reverse()
    out = list(system)
    for msg in kept:
        role = msg.get("role")
        content = msg.get("content") or ""
        if role == "tool":
            out.append({"role": "tool", "content": clean_text(content, TOOL_OUTPUT_MAX)})
            continue
        if role == "assistant":
            item = {"role": "assistant", "content": clean_text(content, TOOL_OUTPUT_MAX)}
            if msg.get("tool_calls"):
                item["tool_calls"] = msg["tool_calls"]
            elif calls_from_text(content):
                item["content"] = "[called tools]"
            out.append(item)
            continue
        if role == "user":
            out.append({"role": "user", "content": clean_text(content, MEMORY_CHARS)})
    return out


def extract_url(text: str) -> str:
    match = re.search(r"https?://[^\s'\"<>]+", text, flags=re.I)
    if match:
        return match.group(0).rstrip(".,)")
    if re.search(r"127\.0\.0\.1|localhost", text, flags=re.I):
        return "http://127.0.0.1:3000"
    return "http://127.0.0.1:3000"


def prefetch_data(text: str) -> tuple[str, str] | None:
    lower = text.lower()
    url = extract_url(text)
    analyze_words = ("analyze", "merge", "priorit", "where to target", "where to focus", "focus area")
    profile_words = ("profile", "robots", "sitemap", "ports", "recon", "target")
    local_words = ("127.0.0.1", "localhost", "http", "site", "target")
    if any(w in lower for w in analyze_words) and any(w in lower for w in local_words):
        return "analyze_target", analyze_target(url)
    if any(w in lower for w in profile_words) and any(w in lower for w in local_words):
        if not any(w in lower for w in analyze_words):
            return "profile_target", profile_target(url)
    if "inspect" in lower and any(w in lower for w in local_words):
        return "inspect_url", inspect_url(url)
    if "scan" in lower and ("127.0.0.1" in lower or "localhost" in lower):
        return "scan_local", scan_local(url)
    return None


def wants_tools(text: str) -> bool:
    lowered = text.lower()
    hints = (
        "file", "code", "read", "list", "dir", "folder", "bug", "function",
        "project", "workspace", "script", "error", "line ", ".py", ".js", ".html",
        "http", "localhost", "127.0.0.1", "site", "page", "server",
        "scan", "vuln", "header", "security", "inspect", "cookie", "tls", "https",
        "profile", "port", "target", "recon", "analyze", "merge", "focus", "priorit",
    )
    return any(hint in lowered for hint in hints)


def chat(messages: list, use_tools: bool) -> dict:
    payload = {"model": MODEL, "messages": prepare_messages(messages), "stream": False}
    if use_tools:
        payload["tools"] = TOOLS
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{HOST}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as res:
            return json.load(res)
    except urllib.error.URLError as exc:
        raise SystemExit(f"ollama unreachable at {HOST}: {exc}") from exc


def calls_from_text(content: str) -> list:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict) and "name" in data:
        data = [data]
    if not isinstance(data, list):
        return []
    calls = []
    for item in data:
        if isinstance(item, dict) and item.get("name"):
            calls.append({"function": {"name": item["name"], "arguments": item.get("arguments") or {}}})
    return calls


def run_tools(message: dict) -> list:
    calls = message.get("tool_calls") or calls_from_text(message.get("content") or "")
    results = []
    for call in calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        raw = fn.get("arguments") or {}
        args = json.loads(raw) if isinstance(raw, str) else raw
        handler = HANDLERS.get(name)
        if handler is None:
            content = f"unknown tool: {name}"
        else:
            try:
                content = handler(**args)
            except Exception as exc:
                content = f"error: {exc}"
        print(f"\n[tool] {name} {args}")
        results.append({"role": "tool", "content": clean_tool_output(name, content)})
    return results


def ask(messages: list, use_tools: bool) -> str:
    seen = set()
    for _ in range(MAX_STEPS):
        data = chat(messages, use_tools)
        message = data.get("message") or {}
        calls = message.get("tool_calls") or calls_from_text(message.get("content") or "")
        if not calls:
            reply = clean_text(message.get("content") or "", TOOL_OUTPUT_MAX)
            message["content"] = reply
            messages.append(message)
            return reply
        fresh = []
        for call in calls:
            fn = call.get("function") or {}
            key = (fn.get("name"), json.dumps(fn.get("arguments") or {}, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            fresh.append(call)
        if not fresh:
            use_tools = False
            messages.append({
                "role": "user",
                "content": "Tools already ran. Reply in plain text. Do not call tools.",
            })
            continue
        message["tool_calls"] = fresh
        messages.append(message)
        messages.extend(run_tools(message))
    return "stopped: too many tool steps"


def clip(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= MEMORY_CHARS:
        return text
    return text[:MEMORY_CHARS] + "..."


def load_memory() -> list:
    if not MEMORY_PATH.is_file():
        return []
    turns = []
    for line in MEMORY_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("role") == "user" and item.get("content"):
            turns.append({"role": "user", "content": clip(item["content"])})
    return turns[-MEMORY_TURNS:]


def save_turn(role: str, content: str) -> None:
    with MEMORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"role": role, "content": clip(content)}) + "\n")


def main() -> None:
    global ROOT
    if len(sys.argv) > 1:
        os.chdir(sys.argv[1])
        ROOT = Path.cwd().resolve()
    remembered = load_memory()
    print(f"model: {MODEL}")
    print(f"workspace: {ROOT}")
    print(f"memory turns: {len(remembered)}")
    print("empty line exits, /clear wipes memory")
    messages = [
        {
            "role": "system",
            "content": (
                "You are a coding assistant. Remember earlier user and assistant turns "
                "and use them when the user refers to previous messages. For greetings, "
                "reply in plain text and do not call tools. Use list_dir and read_file "
                "for workspace files. Use fetch_url for any http or https URL. "
                "scan_local only for http://127.0.0.1 or http://localhost. "
                "inspect_url for a passive review of any http or https URL the user names. "
                "profile_target for a full localhost report including robots.txt and sitemap. "
                "analyze_target to merge scans and rank where to focus review. "
                "Report only what tools return. Do not invent headers or files. "
                "Do not read source files unless the user asks. After tool results, "
                "summarize in plain text."
            ),
        }
    ]
    messages.extend(remembered)
    while True:
        try:
            line = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            return
        if line == "/clear":
            MEMORY_PATH.unlink(missing_ok=True)
            messages[:] = [messages[0]]
            print("memory cleared")
            continue
        messages.append({"role": "user", "content": line})
        prefetch = prefetch_data(line)
        if prefetch:
            tool_name, raw = prefetch
            answer = clean_tool_output(tool_name, raw)
            print(f"\n[tool] {tool_name} (auto)")
            print(answer)
        else:
            answer = ask(messages, wants_tools(line))
            print(answer)
        save_turn("user", line)
        save_turn("assistant", answer)
        messages[:] = prepare_messages(messages)


if __name__ == "__main__":
    main()
