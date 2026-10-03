"""Grab service banners — version intel drives exploit choice, not spray."""

from __future__ import annotations

import socket


def service_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(512)
            except socket.timeout:
                data = b""
            if data:
                return data.decode("utf-8", errors="replace").strip()
            # SMB / some services need a probe
            if port in (445, 139):
                sock.send(b"\x00\x00\x00\x85\xffSMB\x72")
                try:
                    data = sock.recv(512)
                    if data:
                        return data.decode("utf-8", errors="replace").strip()[:200]
                except socket.timeout:
                    pass
    except OSError:
        pass
    return ""


def format_banner(port: int, banner: str) -> str:
    if not banner:
        return "tcp open"
    clean = " ".join(banner.split())[:160]
    return f"tcp open banner={clean}"
