"""Target profile schema."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LoginTarget:
    path: str
    user_field: str
    pass_field: str
    extra_fields: dict[str, str] = field(default_factory=dict)
    success_markers: tuple[str, ...] = ("logout", "dashboard", "welcome")
    fail_markers: tuple[str, ...] = ("invalid", "incorrect", "failed", "denied")


@dataclass
class Surface:
    category: str
    path: str
    param: str
    note: str = ""


@dataclass
class TargetProfile:
    name: str
    description: str
    default_creds: list[tuple[str, str]]
    probe_paths: tuple[str, ...]
    surfaces: list[Surface]
    login_targets: list[LoginTarget]
    service_ports: dict[int, str]
    takeover_hints: list[str]
