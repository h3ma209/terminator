"""Target profiles — lab-specific attack knowledge."""

from __future__ import annotations

from terminator.profiles.metasploitable import METASPLOITABLE, detect_metasploitable
from terminator.profiles.base import TargetProfile

PROFILES: dict[str, TargetProfile] = {
    "metasploitable": METASPLOITABLE,
}


def detect_profile(host: str, banner_text: str = "", page_title: str = "") -> TargetProfile | None:
    blob = f"{banner_text} {page_title}".lower()
    if detect_metasploitable(host, blob):
        return METASPLOITABLE
    if "metasploitable" in blob:
        return METASPLOITABLE
    return None


def get_profile(name: str) -> TargetProfile | None:
    return PROFILES.get(name)
