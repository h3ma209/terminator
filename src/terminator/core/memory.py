"""Session memory, findings, and snapshots."""

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import config


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
