"""One-shot import rewriter for package restructure."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "terminator"

REPLACEMENTS = [
    (r"\bfrom attack_engine import\b", "from terminator.pentest.attack_engine import"),
    (r"\bfrom autonomous import\b", "from terminator.pentest.autonomous import"),
    (r"\bfrom memory_store import\b", "from terminator.core.memory import"),
    (r"\bfrom ollama_client import\b", "from terminator.core.ollama import"),
    (r"\bfrom targets import\b", "from terminator.core.targets import"),
    (r"\bfrom chat_utils import\b", "from terminator.agent.chat_utils import"),
    (r"\bfrom cleanup import\b", "from terminator.agent.cleanup import"),
    (r"\bfrom help_text import\b", "from terminator.agent.help import"),
    (r"\bfrom refusal import\b", "from terminator.agent.refusal import"),
    (r"\bfrom router import\b", "from terminator.agent.router import"),
    (r"\bfrom skill_mode import\b", "from terminator.agent.skill_mode import"),
    (r"\bfrom tool_calls import\b", "from terminator.agent.tool_calls import"),
    (r"\bimport config\b", "from terminator import config"),
    (r"\bfrom tools\.analyze import\b", "from terminator.tools.recon.analyze import"),
    (r"\bfrom tools\.api_routes import\b", "from terminator.tools.recon.api_routes import"),
    (r"\bfrom tools\.profile import\b", "from terminator.tools.recon.profile import"),
    (r"\bfrom tools\.playbook import\b", "from terminator.tools.recon.playbook import"),
    (r"\bfrom tools\.auth_skills import\b", "from terminator.tools.skills.auth_skills import"),
    (r"\bfrom tools\.injection_skills import\b", "from terminator.tools.skills.injection_skills import"),
    (r"\bfrom tools\.network_skills import\b", "from terminator.tools.skills.network_skills import"),
    (r"\bfrom tools\.passive_skills import\b", "from terminator.tools.skills.passive_skills import"),
    (r"\bfrom tools\.redirect import\b", "from terminator.tools.skills.redirect import"),
    (r"\bfrom tools\.sqli import\b", "from terminator.tools.skills.sqli import"),
    (r"\bfrom tools\.traversal import\b", "from terminator.tools.skills.traversal import"),
    (r"\bfrom tools\.xss import\b", "from terminator.tools.skills.xss import"),
    (r"\bfrom tools\.skills import\b", "from terminator.tools.skills import"),
    (r"\bfrom tools\.http import\b", "from terminator.tools.http import"),
    (r"\bfrom tools\.probe_http import\b", "from terminator.tools.probe_http import"),
    (r"\bfrom tools\.web import\b", "from terminator.tools.web import"),
    (r"\bfrom tools\.workspace import\b", "from terminator.tools.workspace import"),
    (r"\bfrom tools\.schemas import\b", "from terminator.tools.schemas import"),
    (r"\bfrom tools import\b", "from terminator.tools import"),
]


def rewrite(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    original = text
    for pattern, repl in REPLACEMENTS:
        text = re.sub(pattern, repl, text)
    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> None:
    changed = 0
    for path in PKG.rglob("*.py"):
        if rewrite(path):
            changed += 1
            print(f"updated {path.relative_to(ROOT)}")
    print(f"done — {changed} file(s)")


if __name__ == "__main__":
    main()
