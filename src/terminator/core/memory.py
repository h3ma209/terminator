"""Session memory, findings, and snapshots."""

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from terminator import config


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_jwt(token: str) -> dict | None:
    try:
        body = token.split(".")[1]
        body += "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(body))
    except Exception:
        return None


def clip(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= config.MEMORY_CHARS:
        return text
    return text[: config.MEMORY_CHARS] + "..."


def load_memory() -> list:
    if not config.MEMORY_PATH.is_file():
        return []
    turns = []
    for line in config.MEMORY_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("role") == "user" and item.get("content"):
            turns.append({"role": "user", "content": clip(item["content"])})
    return turns[-config.MEMORY_TURNS :]


def save_turn(role: str, content: str) -> None:
    with config.MEMORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"role": role, "content": clip(content)}) + "\n")


def load_findings() -> dict:
    if not config.FINDINGS_PATH.is_file():
        return {}
    try:
        return json.loads(config.FINDINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_findings(data: dict) -> None:
    config.FINDINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def snapshot_path(name: str) -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", name)
    return config.REPORTS_DIR / f"{safe}.json"


def list_snapshots() -> list[Path]:
    if not config.REPORTS_DIR.is_dir():
        return []
    return sorted(config.REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)


def resolve_snapshot(path: str) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    if candidate.is_file():
        return candidate
    under = config.REPORTS_DIR / path
    if under.is_file():
        return under
    under = config.REPORTS_DIR / f"{path}.json"
    if under.is_file():
        return under
    return None


def save_snapshot(data: dict) -> Path:
    name = f"{data['target'].replace('://', '_').replace(':', '_')}_{data['timestamp'].replace(':', '-')}"
    path = snapshot_path(name)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _target_key(target: str) -> str:
    safe = re.sub(r"[^\w.-]", "_", target.replace("://", "_"))
    return safe[:120]


def target_learnings_path(target: str) -> Path:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    return config.DATA_DIR / f"learnings_{_target_key(target)}.json"


def load_target_learnings(target: str) -> dict:
    path = target_learnings_path(target)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_target_learnings(target: str, data: dict) -> None:
    path = target_learnings_path(target)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def update_target_learnings(
    target: str,
    *,
    framework: str = "",
    archetype: str = "",
    dead_families: list[str] | None = None,
    dead_actions: list[str] | None = None,
    confirmed_categories: list[str] | None = None,
    confirmed_chains: list[str] | None = None,
    endpoints: list[str] | None = None,
    reflection_hints: list[str] | None = None,
) -> dict:
    """Merge per-target memory for smarter repeat runs.

    Learnings are also keyed by archetype so what worked on one PHP lab or one
    SPA informs the next target of the same class.
    """
    data = load_target_learnings(target)
    data["target"] = target
    data["updated"] = now()
    if framework:
        data["framework"] = framework
    if archetype:
        data["archetype"] = archetype
    if dead_families:
        prev = set(data.get("dead_families") or [])
        data["dead_families"] = sorted(prev | set(dead_families))
    if dead_actions:
        prev = set(data.get("dead_actions") or [])
        data["dead_actions"] = sorted(prev | set(dead_actions))
    if confirmed_categories:
        prev = set(data.get("confirmed_categories") or [])
        data["confirmed_categories"] = sorted(prev | set(confirmed_categories))
    if confirmed_chains:
        prev = set(data.get("confirmed_chains") or [])
        data["confirmed_chains"] = sorted(prev | set(confirmed_chains))
    if endpoints:
        prev = set(data.get("known_endpoints") or [])
        data["known_endpoints"] = sorted(prev | set(endpoints))[:200]
    if reflection_hints and archetype:
        hints = data.get("reflection_hints") or {}
        prev = set(hints.get(archetype) or [])
        hints[archetype] = sorted(prev | set(reflection_hints))[:30]
        data["reflection_hints"] = hints
    save_target_learnings(target, data)
    return data


def archetype_for(framework: str = "", markers: list[str] | None = None, is_lab: bool = False) -> str:
    """Coarse target class so learnings transfer between similar targets."""
    fw = (framework or "").lower()
    blob = " ".join(markers or []).lower()
    if fw in ("nextjs", "react", "angular", "vue"):
        return "spa"
    if "php" in fw or "php" in blob or any(m in blob for m in ("dvwa", "phpmyadmin", "wordpress")):
        return "php_app"
    if is_lab:
        return "lab_vm"
    if any(m in blob for m in ("nmap:", "ssh", "smb", "ftp")):
        return "service_host"
    return "generic_web"
