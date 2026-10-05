"""External tool runner — curl-backed HTTP plus optional CLI security tools.

HTTP goes through curl so custom verbs (PUT/PROPFIND), raw headers, and binary
bodies behave consistently. External scanners (nmap/smbclient/whatweb) are
wrapped with graceful "missing tool" results instead of raising.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from terminator.core import platform as plat


@dataclass
class HttpResult:
    status: int | str
    headers: dict
    body: str
    url: str
    method: str = "GET"
    error: str = ""

    @property
    def ok(self) -> bool:
        return isinstance(self.status, int) and self.status < 400


@dataclass
class ToolResult:
    tool: str
    ok: bool
    stdout: str = ""
    stderr: str = ""
    parsed: dict = field(default_factory=dict)
    note: str = ""


class ToolRunner:
    """Facade over curl and external CLI tools. Thread-unsafe; one per engagement."""

    def __init__(self, timeout: int = 12) -> None:
        self.timeout = timeout
        self._have_cache: dict[str, bool] = {}
        self.log: list[str] = []

    def have(self, tool: str) -> bool:
        if tool not in self._have_cache:
            self._have_cache[tool] = shutil.which(tool) is not None
        return self._have_cache[tool]

    def _record(self, line: str) -> None:
        self.log.append(line)
        if len(self.log) > 200:
            self.log = self.log[-200:]

    # ---- HTTP via curl -------------------------------------------------
    def curl_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        data: bytes | str | None = None,
        timeout: int | None = None,
        follow_redirects: bool = True,
        max_body: int = 32000,
    ) -> HttpResult:
        if not self.have("curl"):
            return HttpResult("error", {}, "", url, method, error="curl missing: " + plat.install_hint("curl"))

        timeout = timeout or self.timeout
        cmd = [
            "curl", "-sS", "-i",
            "--max-time", str(timeout),
            "-X", method.upper(),
            "-A", "terminator-bounty/1.0",
        ]
        if follow_redirects:
            cmd.append("-L")
        for key, val in (headers or {}).items():
            cmd += ["-H", f"{key}: {val}"]
        if data is not None:
            raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
            cmd += ["--data-binary", "@-"]
            proc = self._run(cmd + [url], input_bytes=bytes(raw))
        else:
            proc = self._run(cmd + [url])

        self._record(f"curl -X {method.upper()} {url} -> rc={proc.returncode}")
        if proc.returncode != 0:
            return HttpResult("error", {}, "", url, method, error=proc.stderr.decode("utf-8", "replace")[:300])
        return self._parse_curl(proc.stdout.decode("utf-8", "replace"), url, method, max_body)

    @staticmethod
    def _parse_curl(raw: str, url: str, method: str, max_body: int) -> HttpResult:
        # curl -i with -L may emit several header blocks; keep the last.
        head, _, body = raw.rpartition("\r\n\r\n")
        if not head:
            head, _, body = raw.rpartition("\n\n")
        blocks = re.split(r"\r?\n\r?\n", head) if head else []
        last_headers = blocks[-1] if blocks else head
        status: int | str = "error"
        headers: dict = {}
        first = True
        for line in last_headers.splitlines():
            if first:
                m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
                if m:
                    status = int(m.group(1))
                first = False
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return HttpResult(status, headers, body[:max_body], url, method.upper())

    def _run(self, cmd: list[str], input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd, input=input_bytes, capture_output=True,
                timeout=self.timeout + 5,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 28, b"", b"timeout")
        except Exception as exc:  # noqa: BLE001
            return subprocess.CompletedProcess(cmd, 1, b"", str(exc).encode())

    # ---- external scanners --------------------------------------------
    def nmap(self, host: str, ports: str = "", service_scan: bool = True) -> ToolResult:
        if not self.have("nmap"):
            return ToolResult("nmap", False, note="missing: " + plat.install_hint("nmap"))
        cmd = ["nmap", "-Pn", "-T4", "--open"]
        if service_scan:
            cmd.append("-sV")
        if ports:
            cmd += ["-p", ports]
        cmd.append(host)
        proc = self._run(cmd)
        out = proc.stdout.decode("utf-8", "replace")
        self._record(f"nmap {host} -> rc={proc.returncode}")
        return ToolResult("nmap", proc.returncode == 0, out, proc.stderr.decode("utf-8", "replace"), {"raw": out})

    def smb_probe(self, host: str) -> ToolResult:
        if not self.have("smbclient"):
            return ToolResult("smbclient", False, note="missing: " + plat.install_hint("smbclient"))
        proc = self._run(["smbclient", "-N", "-L", f"//{host}/"])
        out = proc.stdout.decode("utf-8", "replace")
        self._record(f"smbclient -L {host} -> rc={proc.returncode}")
        return ToolResult("smbclient", proc.returncode == 0, out, proc.stderr.decode("utf-8", "replace"))

    def whatweb(self, url: str) -> ToolResult:
        if not self.have("whatweb"):
            return ToolResult("whatweb", False, note="missing: " + plat.install_hint("whatweb"))
        proc = self._run(["whatweb", "--no-errors", "-a", "1", url])
        out = proc.stdout.decode("utf-8", "replace")
        self._record(f"whatweb {url} -> rc={proc.returncode}")
        return ToolResult("whatweb", proc.returncode == 0, out, proc.stderr.decode("utf-8", "replace"))
