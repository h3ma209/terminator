"""OS detection and tool install hints — never auto-installs."""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass

# tool -> (brew formula, apt package)
_PACKAGES = {
    "curl": ("curl", "curl"),
    "nmap": ("nmap", "nmap"),
    "smbclient": ("samba", "smbclient"),
    "whatweb": ("whatweb", "whatweb"),
    "nikto": ("nikto", "nikto"),
    "sqlmap": ("sqlmap", "sqlmap"),
}

# python modules that gate optional chains
_PIP = {
    "pymysql": "pymysql",
    "paramiko": "paramiko",
    "playwright": "playwright",
    "nmap": "python-nmap",  # module name 'nmap' ships in python-nmap
}


def detect_os() -> str:
    sys = platform.system().lower()
    if sys == "darwin":
        return "darwin"
    if sys == "linux":
        return "linux"
    return sys or "unknown"


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def install_hint(tool: str) -> str:
    brew, apt = _PACKAGES.get(tool, (tool, tool))
    os_name = detect_os()
    if os_name == "darwin":
        return f"brew install {brew}"
    if os_name == "linux":
        return f"sudo apt-get install -y {apt}"
    return f"install {tool} via your package manager"


def _have_module(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


@dataclass
class ToolStatus:
    name: str
    kind: str  # binary | python
    present: bool
    hint: str


def doctor_report() -> list[ToolStatus]:
    """Status of every external binary and optional python module."""
    rows: list[ToolStatus] = []
    for tool in _PACKAGES:
        rows.append(ToolStatus(tool, "binary", have(tool), install_hint(tool)))
    for mod, pkg in _PIP.items():
        rows.append(ToolStatus(mod, "python", _have_module(mod), f"pip install {pkg}"))
    return rows


def format_doctor() -> str:
    os_name = detect_os()
    lines = [f"=== terminator doctor (os={os_name}) ===", ""]
    missing: list[str] = []
    for row in doctor_report():
        mark = "ok " if row.present else "MISSING"
        lines.append(f"  [{mark}] {row.kind:<6} {row.name}")
        if not row.present:
            lines.append(f"            -> {row.hint}")
            missing.append(row.name)
    lines.append("")
    if missing:
        lines.append(f"missing ({len(missing)}): {', '.join(missing)}")
        lines.append("install the binaries above, then: pip install -r requirements.txt")
        lines.append("nothing is installed automatically — run the commands yourself")
    else:
        lines.append("all tools present")
    return "\n".join(lines)
