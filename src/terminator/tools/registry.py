"""Tool registry."""

from terminator.tools.recon.analyze import analyze_target
from terminator.tools.recon.api_routes import fetch_api_routes
from terminator.tools.recon.playbook import (
    check_auth_flow,
    compare_runs,
    map_site,
    run_playbook,
    show_findings,
)
from terminator.tools.recon.profile import profile_target
from terminator.tools.schemas import TOOLS
from terminator.tools.skills import SKILL_DEFS, list_skills, run_skill, run_skill_battery
from terminator.tools.web import fetch_url, inspect_url, scan_local
from terminator.tools.workspace import list_dir, read_file

HANDLERS = {
    "list_dir": list_dir,
    "read_file": read_file,
    "fetch_url": fetch_url,
    "scan_local": scan_local,
    "inspect_url": inspect_url,
    "profile_target": profile_target,
    "analyze_target": analyze_target,
    "fetch_api_routes": fetch_api_routes,
    "run_playbook": run_playbook,
    "check_auth_flow": check_auth_flow,
    "map_site": map_site,
    "compare_runs": compare_runs,
    "show_findings": show_findings,
    "list_skills": list_skills,
    "run_skill": run_skill,
    "run_skill_battery": run_skill_battery,
}


def _run_autonomous_engagement(*args, **kwargs):
    from terminator.pentest.autonomous import run_autonomous_engagement
    return run_autonomous_engagement(*args, **kwargs)


HANDLERS["run_autonomous_engagement"] = _run_autonomous_engagement

for _name, _spec in SKILL_DEFS.items():
    HANDLERS[_name] = _spec["handler"]

__all__ = ["HANDLERS", "TOOLS"]
