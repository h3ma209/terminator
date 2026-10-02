"""Skill registry — model supplies params, handler runs probe."""

from tools.xss import check_xss, probe_xss

# name -> (handler, ollama schema fragment)
SKILL_DEFS = {
    "probe_xss": {
        "description": (
            "Test one GET param for reflected XSS using a payload you craft. "
            "Use after finding a form/search endpoint. "
            "Craft context-aware payloads (e.g. <script>alert(1)</script>, "
            "\"><svg/onload=alert(1)>, javascript: URLs)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL e.g. http://127.0.0.1:3000"},
                "path": {"type": "string", "description": "Path e.g. /search"},
                "param": {"type": "string", "description": "Query param name e.g. q"},
                "payload": {
                    "type": "string",
                    "description": "XSS probe string you crafted; injected verbatim into the param",
                },
            },
            "required": ["target", "path", "param", "payload"],
        },
        "handler": probe_xss,
    },
    "check_xss": {
        "description": (
            "Auto-scan localhost for reflected XSS on GET forms and search params. "
            "Optional: pass custom payload(s) to use instead of defaults."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "payload": {"type": "string", "description": "Custom XSS probe for all discovered params"},
                "payloads": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple payloads to try per param",
                },
                "path": {"type": "string", "description": "Limit scan to one path e.g. /search"},
                "param": {"type": "string", "description": "Limit scan to one param e.g. q"},
            },
            "required": ["target"],
        },
        "handler": check_xss,
    },
}


def skill_tool_schemas() -> list:
    return [
        {
            "type": "function",
            "function": {"name": name, **{k: v for k, v in spec.items() if k != "handler"}},
        }
        for name, spec in SKILL_DEFS.items()
    ]


def probe_only_schemas() -> list:
    spec = SKILL_DEFS["probe_xss"]
    return [
        {
            "type": "function",
            "function": {"name": "probe_xss", **{k: v for k, v in spec.items() if k != "handler"}},
        }
    ]


def _probe_ok(hints: dict) -> bool:
    from memory_store import load_findings

    probe = load_findings().get("last_probe") or {}
    want_path = (hints.get("path") or "/search").rstrip("/") or "/search"
    got_path = (probe.get("path") or "").rstrip("/")
    return bool(probe) and got_path == want_path and probe.get("skill") == "probe_xss"


def run_craft_xss(user_line: str, ask_fn, messages: list | None = None) -> str:
    """Model crafts payload; agent enforces path/target and fixes bad tool calls."""
    from skill_mode import SEARCH_DEFAULTS, build_skill_prompt, extract_payload, parse_skill_hints
    from tools.xss import probe_xss

    hints = parse_skill_hints(user_line)
    path = hints.get("path") or SEARCH_DEFAULTS["path"]
    param = hints.get("param") or SEARCH_DEFAULTS["param"]
    target = hints["target"]

    work = [
        {"role": "system", "content": build_skill_prompt(user_line)},
        {"role": "user", "content": user_line},
    ]
    answer = ask_fn(work, use_tools=True, tools=probe_only_schemas())
    if messages is not None:
        messages.extend(work[2:])

    if _probe_ok(hints):
        return answer

    payload = extract_payload(answer) or "<script>alert(1)</script>"
    print(f"\n[skill fix — model missed {path}?{param}=, running probe_xss directly]")
    result = probe_xss(target, path, param, payload)
    verdict = "Yes — vulnerable." if "vulnerable: True" in result else "No — not vulnerable."
    if answer.strip() and "<tool>" not in answer:
        return f"{result}\n\n{verdict}\n{answer.strip()}"
    return f"{result}\n\n{verdict}"


def list_skills() -> str:
    lines = ["=== agent skills ===", "Model crafts params; tool executes on localhost.", ""]
    for name, spec in SKILL_DEFS.items():
        lines.append(f"  {name}")
        lines.append(f"    {spec['description']}")
        props = spec["parameters"].get("properties", {})
        req = spec["parameters"].get("required", [])
        for pname, pdef in props.items():
            mark = " (required)" if pname in req else ""
            lines.append(f"    - {pname}{mark}: {pdef.get('description', pdef.get('type', ''))}")
        lines.append("")
    return "\n".join(lines).strip()


def run_skill(name: str, **kwargs) -> str:
    spec = SKILL_DEFS.get(name)
    if not spec:
        known = ", ".join(sorted(SKILL_DEFS))
        return f"unknown skill: {name}. known: {known}"
    handler = spec["handler"]
    return handler(**kwargs)
