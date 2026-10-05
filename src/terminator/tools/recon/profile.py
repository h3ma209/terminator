"""Localhost target profiling."""

import socket

from terminator import config
from terminator.tools.http import (
    fetch_text,
    header_report,
    http_probe,
    is_allowed_host,
    parse_target,
)
from terminator.tools.recon.banners import format_banner, service_banner
from terminator.tools.recon.nmap_scan import PortInfo, scan_host


def _enrich_port_line(host: str, pinfo: PortInfo, scan_method: str) -> str:
    port = pinfo.port
    if port in config.HTTP_PROBE_PORTS:
        detail, _ = http_probe(host, port)
        return f"  {port}/{pinfo.label()}: {detail}"
    if scan_method == "nmap" and pinfo.detail:
        return pinfo.format_line()
    banner = service_banner(host, port)
    detail = format_banner(port, banner)
    return f"  {port}/{pinfo.label()}: {detail}"


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

    ports_to_scan = sorted(set(config.COMMON_PORTS) | ({hint_port} if hint_port else set()))
    scan = scan_host(host, ports=list(ports_to_scan), extended=False)

    lines = [
        f"target: {target}",
        f"host: {host}",
        f"resolved: {resolved}",
        "open ports:",
    ]

    web_base_url = None
    all_ports: list[PortInfo] = list(scan.ports)

    if len(scan.open_ports) >= 2:
        ext = scan_host(host, extended=True)
        seen = {p.port for p in all_ports}
        for p in ext.ports:
            if p.port not in seen:
                all_ports.append(p)
                seen.add(p.port)

    if not all_ports:
        lines.append("  none open")
    else:
        for pinfo in sorted(all_ports, key=lambda p: p.port):
            line = _enrich_port_line(host, pinfo, scan.method)
            lines.append(line)
            port = pinfo.port
            if port in config.HTTP_PROBE_PORTS:
                _, base = http_probe(host, port)
                if base and not web_base_url:
                    web_base_url = base.rstrip("/")
            if hint_port and port == hint_port:
                web_base_url = web_base_url or f"http://{host}:{hint_port}"

    lines.append(f"scan method: {scan.method}")
    lines.append(f"scanned {len(ports_to_scan)} ports via {scan.method}")

    if web_base_url:
        lines.extend([
            "",
            header_report(web_base_url + "/"),
            "",
            "robots.txt:",
            fetch_text(web_base_url + "/robots.txt", 800),
            "",
            "sitemap.xml:",
            fetch_text(web_base_url + "/sitemap.xml", 800),
        ])
    return "\n".join(lines)
