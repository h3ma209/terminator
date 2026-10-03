"""Deprecated — profiles disabled. Agent uses discovery-only intel."""

from terminator.profiles.base import TargetProfile

# Kept for legacy imports only; never used at runtime.
METASPLOITABLE = TargetProfile(
    name="deprecated",
    description="profiles disabled — use discovery",
    default_creds=[],
    probe_paths=(),
    surfaces=[],
    login_targets=[],
    service_ports={},
    takeover_hints=[],
)
