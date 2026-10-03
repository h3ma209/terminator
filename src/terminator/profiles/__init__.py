"""Target profiles — disabled; agent uses discovery-only intel."""

from __future__ import annotations

from terminator.profiles.base import TargetProfile


def detect_profile(host: str, banner_text: str = "", page_title: str = "") -> TargetProfile | None:
    """Always unknown — no cheat-sheet profiles."""
    return None


def get_profile(name: str) -> TargetProfile | None:
    return None
