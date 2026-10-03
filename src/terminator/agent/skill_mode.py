"""Skill mode — model crafts payload; agent knows all technique variations."""

from __future__ import annotations

import re

from terminator.core.memory import load_findings
from terminator.core.targets import extract_url
from terminator.catalog import (
    PATH_MAP,
    SKILL_CONFIG,
    build_probe_plan,
    default_payload,
    format_techniques_for_prompt,
    get_technique,
    resolve_technique,
    wants_all_variations,
)

# backward compat — enriched with fallback_payload per skill
SKILL_TYPES: dict[str, dict] = {
    name: {
        **cfg,
        "fallback_payload": default_payload(name) if name in {
            "xss", "sqli", "redirect", "traversal", "idor", "cors", "ssrf", "cmdi", "ssti", "crlf",
        } else (
            '{"username":"demo","password":"demo","role":"admin"}' if name == "mass_assignment" else ""
        ),
    }
    for name, cfg in SKILL_CONFIG.items()
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
    if lower in {"/skills", "skills", "list skills", "/catalog", "catalog"}:
        return False
    craft_hints = (
        "craft", "try payload", "test with", "probe with", "inject",
        "use payload", "custom payload", "run skill", "all variations",
        "all techniques", "try all", "technique",
    )
    if any(h in lower for h in craft_hints):
        return True
    for cfg in SKILL_TYPES.values():
        if any(k in lower for k in cfg["keywords"]) and any(
            w in lower for w in ("craft", "try", "test", "payload", "inject", "probe", "technique")
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
    named = resolve_technique(skill, text)
    if named:
        hints["technique"] = named[0]
        hints["payload"] = named[1]
    if wants_all_variations(text):
        hints["all_variations"] = True
    return hints


def build_skill_prompt(text: str, skill: str | None = None) -> str:
    skill = skill or detect_skill_type(text)
    cfg = SKILL_TYPES[skill]
    hints = parse_skill_hints(text, skill)
    techniques_block = format_techniques_for_prompt(skill)
    multi = (
        "User asked for ALL variations — call the probe once per technique listed."
        if hints.get("all_variations")
        else "Pick one technique OR craft a custom payload. You may call probe multiple times with different techniques."
    )
    return (
        f"You test {skill} on localhost using {cfg['probe_tool']}. "
        f"Use exactly: target={hints['target']}, path={hints['path']}, param={hints['param']}. "
        f"{cfg['instruction']}\n"
        f"Known techniques and injection styles:\n{techniques_block}\n"
        f"{multi} "
        f"Name the technique in your reply when you use a catalog payload."
    )


def extract_payload(text: str, skill: str = "xss") -> str:
    if not text:
        return SKILL_TYPES.get(skill, SKILL_TYPES["xss"])["fallback_payload"]

    named = resolve_technique(skill, text)
    if named:
        return named[1]

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
        for pattern in (
            r"(<script[^>]*>.*?</script>)",
            r"(<img[^>]*onerror[^>]*>)",
            r"(<svg[^>]*onload[^>]*>)",
            r"(<details[^>]*ontoggle[^>]*>)",
            r"(<[^>]*on\w+[^>]*>)",
        ):
            match = re.search(pattern, text, flags=re.I | re.S)
            if match:
                return match.group(1)

    if skill in {"sqli", "traversal", "crlf"}:
        match = re.search(r"(\.{2,}/[\w./%-]+)", text)
        if match:
            return match.group(1)
        match = re.search(r"(['\"].*?(?:OR|--|UNION).+?['\"])", text, flags=re.I)
        if match:
            return match.group(1).strip("'\"")

    if skill in {"redirect", "cors", "ssrf"}:
        match = re.search(r"(https?://[^\s'\"<>]+|//[^\s'\"<>]+|file://[^\s'\"<>]+)", text, flags=re.I)
        if match:
            return match.group(1)

    if skill == "cmdi":
        for pattern in (
            r"([\w.]+;[\w]+)",
            r"([\w.]+\|[\w]+)",
            r"([\w.]+`[\w]+`)",
            r"([\w.]+&&[\w]+)",
        ):
            match = re.search(pattern, text)
            if match:
                return match.group(1)

    if skill == "ssti":
        for pattern in (r"(\{\{[^}]+\}\})", r"(\$\{[^}]+\})"):
            match = re.search(pattern, text)
            if match:
                return match.group(1)

    if skill == "idor":
        tech = get_technique(skill, text)
        if tech:
            return tech.payload

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
        technique = probe.get("technique", "")
        contexts = ", ".join(probe.get("contexts") or probe.get("signals") or []) or "none"
        tech_line = f"\n  technique: {technique}" if technique else ""
        if probe.get("vulnerable"):
            return (
                f"Yes - {skill} vulnerable on {path} ({param}).{tech_line}\n"
                f"  payload: {payload}\n  signals: {contexts}"
            )
        return f"No - {skill} not vulnerable.{tech_line}\n  last payload: {payload}"
    return "No probe data yet. Try: craft sqli tautology on /user http://127.0.0.1:3000"
