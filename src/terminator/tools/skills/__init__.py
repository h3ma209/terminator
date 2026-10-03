"""Skill registry — model supplies params, handler runs probe."""

from terminator.agent.skill_mode import SKILL_TYPES, build_skill_prompt, detect_skill_type, extract_payload, parse_skill_hints
from terminator.tools.skills.auth_skills import (
    check_auth_bypass,
    check_idor,
    check_rate_limit,
    probe_idor,
    probe_jwt,
    probe_mass_assignment,
)
from terminator.tools.skills.injection_skills import check_cmdi, check_ssti, probe_cmdi, probe_ssti
from terminator.tools.skills.network_skills import check_cors, check_crlf, check_ssrf, probe_cors, probe_crlf, probe_ssrf
from terminator.tools.skills.passive_skills import (
    check_clickjacking,
    check_csrf,
    check_http_methods,
    check_security_headers,
    check_sensitive_leak,
    run_passive_suite,
)
from terminator.tools.skills.redirect import check_redirect, probe_redirect
from terminator.tools.skills.sqli import check_sqli, probe_sqli
from terminator.tools.skills.traversal import check_traversal, probe_traversal
from terminator.tools.skills.xss import check_xss, probe_xss


def _probe_schema(desc: str, path_hint: str, param_hint: str, payload_hint: str) -> dict:
    return {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "path": {"type": "string", "description": path_hint},
            "param": {"type": "string", "description": param_hint},
            "payload": {"type": "string", "description": payload_hint},
        },
        "required": ["target", "path", "param", "payload"],
    }


def _check_schema(desc: str, extra: bool = True) -> dict:
    props = {"target": {"type": "string"}}
    if extra:
        props.update({
            "payload": {"type": "string"},
            "path": {"type": "string"},
            "param": {"type": "string"},
        })
    return {"type": "object", "properties": props, "required": ["target"]}


def _target_schema(desc: str) -> dict:
    return {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}


PROBE_ENTRIES = [
    ("probe_xss", "xss", probe_xss, "Reflected XSS probe.", "/search", "q", "XSS payload"),
    ("probe_sqli", "sqli", probe_sqli, "SQLi probe.", "/user", "id", "SQLi payload"),
    ("probe_redirect", "redirect", probe_redirect, "Open redirect probe.", "/redirect", "url", "External URL"),
    ("probe_traversal", "traversal", probe_traversal, "Path traversal probe.", "/files", "name", "Traversal path"),
    ("probe_jwt", "jwt", probe_jwt, "JWT/auth bypass probe.", "/api/admin", "Authorization", "JWT token"),
    ("probe_idor", "idor", probe_idor, "IDOR probe.", "/user", "id", "Object id"),
    ("probe_mass_assignment", "mass_assignment", probe_mass_assignment, "Mass assignment on login.", "/api/login", "body", "JSON body"),
    ("probe_cors", "cors", probe_cors, "CORS misconfiguration probe.", "/api/cors", "Origin", "Origin URL"),
    ("probe_ssrf", "ssrf", probe_ssrf, "SSRF probe.", "/fetch", "url", "URL to fetch"),
    ("probe_cmdi", "cmdi", probe_cmdi, "Command injection probe.", "/ping", "host", "Shell payload"),
    ("probe_ssti", "ssti", probe_ssti, "SSTI probe.", "/render", "template", "Template payload"),
    ("probe_crlf", "crlf", probe_crlf, "CRLF/header injection probe.", "/echo", "msg", "CRLF payload"),
]

CHECK_ENTRIES = [
    ("check_xss", "xss", check_xss, "Auto-scan reflected XSS."),
    ("check_sqli", "sqli", check_sqli, "Auto-scan SQLi."),
    ("check_redirect", "redirect", check_redirect, "Auto-scan open redirects."),
    ("check_traversal", "traversal", check_traversal, "Auto-scan path traversal."),
    ("check_auth_bypass", "jwt", check_auth_bypass, "JWT none-token + mass assignment battery."),
    ("check_idor", "idor", check_idor, "Auto-scan IDOR on /user."),
    ("check_cors", "cors", check_cors, "Auto-scan CORS."),
    ("check_ssrf", "ssrf", check_ssrf, "Auto-scan SSRF on /fetch."),
    ("check_cmdi", "cmdi", check_cmdi, "Auto-scan command injection."),
    ("check_ssti", "ssti", check_ssti, "Auto-scan SSTI."),
    ("check_crlf", "crlf", check_crlf, "Auto-scan CRLF injection."),
    ("check_rate_limit", "jwt", check_rate_limit, "Login rate limit check."),
    ("check_csrf", "passive", check_csrf, "Find forms missing CSRF tokens."),
    ("check_security_headers", "passive", check_security_headers, "Security header score."),
    ("check_sensitive_leak", "passive", check_sensitive_leak, "Scan for secrets in responses."),
    ("check_clickjacking", "passive", check_clickjacking, "X-Frame-Options / CSP check."),
    ("check_http_methods", "passive", check_http_methods, "Risky HTTP methods on API routes."),
    ("run_passive_suite", "passive", run_passive_suite, "All passive checks."),
]

SKILL_DEFS = {}
PROBE_HANDLERS = {}

for name, skill, handler, desc, path, param, payload in PROBE_ENTRIES:
    SKILL_DEFS[name] = {
        "description": desc,
        "parameters": _probe_schema(desc, path, param, payload),
        "handler": handler,
        "skill": skill,
    }
    PROBE_HANDLERS[name] = handler

for name, skill, handler, desc in CHECK_ENTRIES:
    schema = _target_schema(desc) if name in {
        "check_rate_limit", "check_csrf", "check_security_headers",
        "check_sensitive_leak", "check_clickjacking", "check_http_methods",
        "run_passive_suite", "check_auth_bypass", "check_cors",
    } else _check_schema(desc)
    SKILL_DEFS[name] = {"description": desc, "parameters": schema, "handler": handler, "skill": skill}


def skill_tool_schemas() -> list:
    return [
        {"type": "function", "function": {"name": n, **{k: v for k, v in s.items() if k not in {"handler", "skill"}}}}
        for n, s in SKILL_DEFS.items()
    ]


def probe_schemas_for(skill: str) -> list:
    return [
        {"type": "function", "function": {"name": n, **{k: v for k, v in SKILL_DEFS[n].items() if k not in {"handler", "skill"}}}}
        for n, s in SKILL_DEFS.items() if s.get("skill") == skill and n.startswith("probe_")
    ]


def _probe_ok(hints: dict) -> bool:
    from terminator.core.memory import load_findings

    cfg = SKILL_TYPES.get(hints["skill"], {})
    probe = load_findings().get("last_probe") or {}
    if not probe or probe.get("skill") != cfg.get("probe_tool"):
        return False
    want = (hints.get("path") or "").rstrip("/")
    got = (probe.get("path") or "").rstrip("/")
    if want and got and want != got:
        return False
    return True


def run_craft_skill(user_line: str, ask_fn, messages: list | None = None) -> str:
    skill = detect_skill_type(user_line)
    cfg = SKILL_TYPES[skill]
    hints = parse_skill_hints(user_line, skill)
    path, param, target = hints["path"], hints["param"], hints["target"]
    tool_name = cfg["probe_tool"]
    handler = PROBE_HANDLERS[tool_name]

    work = [
        {"role": "system", "content": build_skill_prompt(user_line, skill)},
        {"role": "user", "content": user_line},
    ]
    answer = ask_fn(work, use_tools=True, tools=probe_schemas_for(skill))
    if messages is not None:
        messages.extend(work[2:])

    if _probe_ok(hints):
        return answer

    payload = extract_payload(answer, skill) or cfg["fallback_payload"]
    print(f"\n[skill fix — running {tool_name}]")
    result = handler(target, path, param, payload)
    verdict = "Yes - vulnerable." if "vulnerable: True" in result else "No - not vulnerable."
    return f"{result}\n\n{verdict}" if "<tool>" in (answer or "") else f"{result}\n\n{verdict}\n{answer.strip()}" if answer.strip() else f"{result}\n\n{verdict}"


run_craft_xss = run_craft_skill


def list_skills() -> str:
    lines = ["=== agent skills ===", "Model crafts payload; tool executes on localhost.", ""]
    groups: dict[str, list] = {}
    for name, spec in SKILL_DEFS.items():
        groups.setdefault(spec.get("skill", "?"), []).append((name, spec))
    for skill in sorted(groups):
        lines.append(f"[{skill}]")
        for name, spec in groups[skill]:
            lines.append(f"  {name} — {spec['description']}")
        lines.append("")
    return "\n".join(lines).strip()


def run_skill(name: str, **kwargs) -> str:
    spec = SKILL_DEFS.get(name)
    if not spec:
        return f"unknown skill: {name}. known: {', '.join(sorted(SKILL_DEFS))}"
    return spec["handler"](**kwargs)


def run_skill_battery(target: str) -> str:
    checks = (
        "check_xss", "check_sqli", "check_redirect", "check_traversal",
        "check_auth_bypass", "check_idor", "check_cors", "check_ssrf",
        "check_cmdi", "check_ssti", "check_crlf", "check_rate_limit",
        "run_passive_suite",
    )
    parts = [run_skill(name, target=target) for name in checks]
    return "\n\n".join(parts)
