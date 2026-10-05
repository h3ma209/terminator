"""Port discovery via python-nmap with socket fallback."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from terminator import config

_SCAN_CACHE: dict[str, "ScanResult"] = {}


@dataclass
class PortInfo:
    port: int
    state: str = "open"
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    detail: str = ""

    def label(self) -> str:
        return config.COMMON_PORTS.get(self.port) or config.EXTENDED_PORTS.get(self.port) or self.service or "unknown"

    def format_line(self) -> str:
        svc = self.service or self.label()
        extra = " ".join(x for x in (self.product, self.version) if x).strip()
        detail = self.detail or (f"tcp open {extra}".strip() if extra else "tcp open")
        return f"  {self.port}/{svc}: {detail}"


@dataclass
class ScanResult:
    host: str
    ports: list[PortInfo] = field(default_factory=list)
    method: str = "socket"  # nmap | socket

    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.state == "open"]

    def has_port(self, port: int) -> bool:
        return port in self.open_ports

    def get(self, port: int) -> PortInfo | None:
        for p in self.ports:
            if p.port == port:
                return p
        return None


def _default_ports(extended: bool = False) -> list[int]:
    ports = set(config.COMMON_PORTS) | set(config.EXTENDED_PORTS if extended else [])
    return sorted(ports)


def _socket_scan(host: str, ports: list[int], timeout: float = 0.4) -> ScanResult:
    found: list[PortInfo] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                label = config.COMMON_PORTS.get(port) or config.EXTENDED_PORTS.get(port, "unknown")
                found.append(PortInfo(port=port, state="open", service=label, detail="tcp open (connect)"))
        except OSError:
            continue
    return ScanResult(host=host, ports=found, method="socket")


def _nmap_scan(host: str, ports: list[int]) -> ScanResult | None:
    try:
        import nmap  # type: ignore
    except ImportError:
        return None

    port_str = ",".join(str(p) for p in ports)
    # -sT TCP connect (no root), --open only reported open ports
    arguments = "-sT -T4 --open -Pn"
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, ports=port_str, arguments=arguments)
    except (nmap.PortScannerError, OSError, Exception):
        return None

    resolved_hosts = scanner.all_hosts()
    if not resolved_hosts:
        return ScanResult(host=host, ports=[], method="nmap")

    # python-nmap keys by resolved IP (localhost → 127.0.0.1)
    scan_key = host if host in resolved_hosts else resolved_hosts[0]

    found: list[PortInfo] = []
    for proto in scanner[scan_key].all_protocols():
        for port in sorted(scanner[scan_key][proto].keys()):
            data = scanner[scan_key][proto][port]
            if data.get("state") != "open":
                continue
            product = data.get("product") or ""
            version = data.get("version") or ""
            service = data.get("name") or ""
            extra = " ".join(x for x in (product, version) if x).strip()
            detail = f"tcp open {extra}".strip() if extra else "tcp open"
            found.append(PortInfo(
                port=int(port),
                state="open",
                protocol=proto,
                service=service,
                product=product,
                version=version,
                detail=detail,
            ))
    return ScanResult(host=host, ports=found, method="nmap")


def scan_host(
    host: str,
    ports: list[int] | None = None,
    *,
    extended: bool = False,
    use_cache: bool = True,
    prefer_nmap: bool = True,
) -> ScanResult:
    """Scan host ports — nmap when available, else TCP connect fallback."""
    port_list = sorted(ports or _default_ports(extended))
    cache_key = f"{host}:{'+'.join(map(str, port_list))}"
    if use_cache and cache_key in _SCAN_CACHE:
        return _SCAN_CACHE[cache_key]

    result: ScanResult | None = None
    if prefer_nmap:
        result = _nmap_scan(host, port_list)
    if result is None:
        result = _socket_scan(host, port_list)

    if use_cache:
        _SCAN_CACHE[cache_key] = result
    return result


def clear_scan_cache() -> None:
    _SCAN_CACHE.clear()


def open_port_numbers(host: str, *, extended: bool = False) -> list[int]:
    return scan_host(host, extended=extended).open_ports


def is_port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    """Check single port — uses cached full scan when available."""
    for cached in _SCAN_CACHE.values():
        if cached.host == host:
            return cached.has_port(port)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def format_scan_report(result: ScanResult, *, ports_scanned: int | None = None) -> list[str]:
    lines = [f"scan method: {result.method}"]
    if not result.ports:
        lines.append("  none open")
    else:
        for p in sorted(result.ports, key=lambda x: x.port):
            lines.append(p.format_line())
    n = ports_scanned or len(_default_ports())
    lines.append(f"scanned {n} ports via {result.method}")
    return lines
