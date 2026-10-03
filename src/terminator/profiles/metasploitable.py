"""Metasploitable 2 — known services, creds, and web apps."""

from __future__ import annotations

from terminator.profiles.base import LoginTarget, Surface, TargetProfile

METASPLOITABLE = TargetProfile(
    name="metasploitable",
    description="Metasploitable 2 — intentionally vulnerable Linux lab VM",
    default_creds=[
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("admin", "admin"),
        ("root", "root"),
        ("root", ""),
        ("postgres", "postgres"),
        ("service", "service"),
        ("tomcat", "tomcat"),
        ("admin", "password"),
        ("manager", "manager"),
    ],
    probe_paths=(
        "/", "/index.html", "/phpinfo.php", "/phpMyAdmin/", "/dvwa/", "/mutillidae/",
        "/twiki/", "/dav/", "/webdav/", "/server-status", "/status",
        "/phpMyAdmin/index.php", "/dvwa/login.php",
    ),
    surfaces=[
        Surface("sqli", "/dvwa/vulnerabilities/sqli/", "id", "DVWA SQLi (needs login)"),
        Surface("xss", "/dvwa/vulnerabilities/xss_r/", "name", "DVWA reflected XSS"),
        Surface("cmdi", "/dvwa/vulnerabilities/exec/", "ip", "DVWA command exec"),
        Surface("traversal", "/dvwa/vulnerabilities/fi/", "page", "DVWA file inclusion"),
        Surface("sqli", "/mutillidae/", "id", "Mutillidae params"),
    ],
    login_targets=[
        LoginTarget(
            "/dvwa/login.php", "username", "password",
            extra_fields={"Login": "Login"},
            success_markers=("logout", "vulnerabilities", "dvwa"),
        ),
        LoginTarget(
            "/phpMyAdmin/index.php", "pma_username", "pma_password",
            extra_fields={"server": "1"},
            success_markers=("navigation", "phpmyadmin", "server_databases"),
            fail_markers=("denied", "cannot log in", "#1045"),
        ),
        LoginTarget(
            "/phpMyAdmin/", "pma_username", "pma_password",
            success_markers=("navigation", "phpmyadmin"),
        ),
    ],
    service_ports={
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        139: "netbios",
        445: "smb",
        3306: "mysql",
        5432: "postgres",
        5900: "vnc",
        6667: "irc",
        8180: "tomcat",
    },
    takeover_hints=[
        "FTP anonymous upload → shell in /var/www",
        "SSH/Telnet msfadmin:msfadmin → direct shell",
        "MySQL root no password → SELECT INTO OUTFILE webshell",
        "phpMyAdmin root login → SQL shell / file read",
        "DVWA admin:password → exploit modules for shell",
        "WebDAV PUT → upload PHP shell to /dav/",
        "vsFTPd 2.3.4 backdoor on port 6200 if version match",
        "Samba usermap_script CVE-2007-2447",
        "UnrealIRCd backdoor on 6667",
    ],
)


def detect_metasploitable(host: str, banner_blob: str) -> bool:
    markers = ("metasploitable", "metasploitable2", "ubuntu; dav/2")
    return any(m in banner_blob.lower() for m in markers)
