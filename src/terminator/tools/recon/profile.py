"""Localhost target profiling."""

import socket

from terminator import config
from terminator.profiles import detect_profile
from terminator.tools.http import (
    fetch_text,
    header_report,
    http_probe,
    is_allowed_host,
    parse_target,
    port_open,
)
from terminator.tools.recon.banners import format_banner, service_banner


def profile_target(target: str) -> str:
    try:
        host, hint_port = parse_target(target)
    except ValueError as exc:
        return f"error: {exc}"
    if not is_allowed_host(host):
        return f"blocked: {host} not in scope (allow_lan or add to targets)"
    try:
        resolved = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
    except OSError as exc:
        return f"error: cannot resolve {host}: {exc}"
    ports = set(config.COMMON_PORTS)
    if hint_port:
        ports.add(hint_port)
    lines = [
        f"target: {target}",
        f"host: {host}",
        f"resolved: {resolved}",
        "open ports:",
    ]
    web_base = None
    if hint_port and port_open(host, hint_port):
        web_base = f"http://{host}:{hint_port}"
    open_count = 0
    banner_blob = ""
    for port in sorted(ports):
        if port_open(host, port):
            open_count += 1
            label = config.COMMON_PORTS.get(port, "unknown")
            if port in config.HTTP_PROBE_PORTS:
                detail, base = http_probe(host, port)
                banner_blob += " " + detail
                if base and not web_base:
                    web_base = base.rstrip("/")
            else:
                banner = service_banner(host, port)
                detail = format_banner(port, banner)
                banner_blob += " " + banner
            lines.append(f"  {port}/{label}: {detail}")

    # Lab VM — widen port set once banner confirms Metasploitable-style stack
    profile = detect_profile(host, banner_blob)
    if profile and profile.service_ports:
        extra = set(profile.service_ports) - ports
        for port in sorted(extra):
            if port_open(host, port):
                open_count += 1
                label = profile.service_ports.get(port, "unknown")
                if port in config.HTTP_PROBE_PORTS:
                    detail, base = http_probe(host, port)
                    banner_blob += " " + detail
                    if base and not web_base:
                        web_base = base.rstrip("/")
                else:
                    banner = service_banner(host, port)
                    detail = format_banner(port, banner)
                    banner_blob += " " + banner
                lines.append(f"  {port}/{label}: {detail}")
    if not open_count:
        lines.append("  none from the common port list")
    lines.append(f"scanned {len(ports)} common ports with short tcp connect probes")
    if web_base:
        lines.extend([
            "",
            header_report(web_base + "/"),
            "",
            "robots.txt:",
            fetch_text(web_base + "/robots.txt", 800),
            "",
            "sitemap.xml:",
            fetch_text(web_base + "/sitemap.xml", 800),
        ])
    return "\n".join(lines)
