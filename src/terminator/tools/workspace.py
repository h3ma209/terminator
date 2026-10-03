"""Workspace file tools."""

from pathlib import Path

import config


def _inside(path: Path) -> Path:
    full = (config.ROOT / path).resolve()
    if not full.is_relative_to(config.ROOT):
        raise ValueError("path escapes workspace")
    return full


def list_dir(path: str) -> str:
    folder = _inside(Path(path))
    if not folder.is_dir():
        return f"not a directory: {path}"
    names = sorted(
        p.name + ("/" if p.is_dir() else "")
        for p in folder.iterdir()
        if p.name not in config.SKIP_DIRS
    )
    return "\n".join(names) if names else "(empty)"


def read_file(path: str) -> str:
    file = _inside(Path(path))
    if not file.is_file():
        return f"not a file: {path}"
    text = file.read_text(encoding="utf-8", errors="replace")
    if len(text) > config.MAX_READ:
        return text[: config.MAX_READ] + "\n...[truncated]"
    return text
