"""Localhost target profiling."""

import socket

from terminator import config
from terminator.tools.http import (
    fetch_text,
    header_report,
    http_probe,
    localhost_only,
    parse_target,
    port_open,
)


def profile_target(target: str) -> str:
    try:
        host, hint_port = parse_target(target)
    except ValueError as exc:
        return f"error: {exc}"
    if not localhost_only(host):
        return "blocked: profile_target only works on 127.0.0.1 or localhost"
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
    for port in sorted(ports):
        if port_open(host, port):
            open_count += 1
            label = config.COMMON_PORTS.get(port, "unknown")
            if port in config.HTTP_PROBE_PORTS:
                detail, base = http_probe(host, port)
                if base and not web_base:
                    web_base = base.rstrip("/")
            else:
                detail = "tcp open"
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
