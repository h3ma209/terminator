"""Tool registry."""

from tools.analyze import analyze_target
from tools.api_routes import fetch_api_routes
from tools.playbook import (
    check_auth_flow,
    compare_runs,
    map_site,
    run_playbook,
    show_findings,
)
from tools.profile import profile_target
from tools.schemas import TOOLS
from tools.web import fetch_url, inspect_url, scan_local
from tools.workspace import list_dir, read_file
from tools.skills import list_skills, run_skill
from tools.xss import check_xss, probe_xss

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
    "check_xss": check_xss,
    "probe_xss": probe_xss,
    "list_skills": list_skills,
    "run_skill": run_skill,
}

__all__ = ["HANDLERS", "TOOLS"]
