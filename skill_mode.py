"""Skill mode — model crafts payload; agent locks path/target."""

import re

from memory_store import load_findings
from targets import extract_url

SEARCH_DEFAULTS = {"path": "/search", "param": "q"}


def wants_skill_mode(text: str) -> bool:
    lower = text.lower().strip()
    if lower in {"/skills", "skills", "list skills"}:
        return False
    craft_hints = (
        "craft", "try payload", "test with", "probe with", "inject",
        "use payload", "custom payload", "run skill", "probe_xss",
    )
    if any(h in lower for h in craft_hints):
        return True
    if "xss" in lower and any(h in lower for h in (
        "craft", "try", "test", "payload", "inject", "<", "svg", "script", "onerror",
    )):
        return True
    if re.search(r"<[^>]+>", text):
        return True
    return False


def wants_probe_followup(text: str) -> bool:
    lower = text.lower().strip()
    hints = (
        "is it vulnerable", "was it vulnerable", "is that vulnerable",
        "did it work", "did it reflect", "what was the result", "vulnerable?",
        "was the payload", "did the payload", "reflected?",
    )
    return any(h in lower for h in hints)


def parse_skill_hints(text: str) -> dict:
    hints = {"target": extract_url(text), "path": "", "param": "q"}
    lower = text.lower()
    if "/search" in lower or re.search(r"\bsearch\b", lower):
        hints.update(SEARCH_DEFAULTS)
        return hints
    match = re.search(r"(/[\w./-]+)", text)
    if match:
        hints["path"] = match.group(1).split("?", 1)[0]
    return hints


def build_skill_prompt(text: str) -> str:
    hints = parse_skill_hints(text)
    path = hints["path"] or SEARCH_DEFAULTS["path"]
    param = hints["param"] or SEARCH_DEFAULTS["param"]
    target = hints["target"]
    return (
        "You test reflected XSS on localhost using probe_xss ONLY. "
        "Do NOT call check_xss. Do NOT use /login or other paths unless the user named them. "
        f"Use exactly: target={target}, path={path}, param={param}. "
        "You choose only the payload string (craft something effective). "
        "Call probe_xss once, then answer in 1-2 plain sentences: vulnerable yes or no."
    )


def extract_payload(text: str) -> str:
    if not text:
        return ""
    fenced = re.search(r"```(?:json|html|text)?\s*(.+?)```", text, flags=re.I | re.S)
    if fenced and "<" in fenced.group(1):
        return fenced.group(1).strip().strip('"').strip("'")
    for pattern in (
        r"(<script[^>]*>.*?</script>)",
        r"(<[^>]*on\w+[^>]*>)",
        r"(\"[^\"]*on\w+[^\"]*\")",
        r"(<svg[^>]*>)",
        r"(<img[^>]+>)",
    ):
        match = re.search(pattern, text, flags=re.I | re.S)
        if match:
            return match.group(1)
    match = re.search(r"payload[:\s]+([^\n]+)", text, flags=re.I)
    if match and "<" in match.group(1):
        return match.group(1).strip().strip('"').strip("'")
    return ""


def answer_probe_followup() -> str:
    data = load_findings()
    probe = data.get("last_probe")
    if probe:
        path = probe.get("path", "?")
        param = probe.get("param", "?")
        payload = probe.get("payload", "?")
        contexts = ", ".join(probe.get("contexts") or []) or "none"
        if probe.get("vulnerable"):
            return (
                f"Yes - vulnerable. GET {path}?{param}= reflects unescaped.\n"
                f"  payload: {payload}\n"
                f"  context: {contexts}"
            )
        return (
            f"No - not vulnerable (or not reflected unescaped) on {path}?{param}=.\n"
            f"  last payload: {payload}"
        )
    xss = data.get("xss") or {}
    hits = xss.get("vulnerable") or []
    if hits:
        hit = hits[0]
        return (
            f"Yes - vulnerable on {hit.get('path')}?{hit.get('param')}=.\n"
            f"  context: {', '.join(hit.get('contexts') or [])}"
        )
    return "No probe data yet. Run: craft xss payload and test /search on http://127.0.0.1:3000"
