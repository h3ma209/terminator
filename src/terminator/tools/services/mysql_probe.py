"""MySQL weak credential probing."""

from __future__ import annotations

import socket
import struct


def _mysql_greeting(host: str, port: int = 3306, timeout: float = 5) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            if len(data) < 5:
                return "short response"
            length = struct.unpack("<I", data[:3] + b"\x00")[0]
            return data[4:min(len(data), 4 + length)].decode("utf-8", errors="replace")
    except OSError as exc:
        return f"error: {exc}"


def _try_pymysql(host: str, user: str, password: str, port: int = 3306) -> tuple[bool, str]:
    try:
        import pymysql  # type: ignore
    except ImportError:
        return False, "pymysql not installed"
    try:
        conn = pymysql.connect(
            host=host, port=port, user=user, password=password,
            connect_timeout=5, read_timeout=5,
        )
        cur = conn.cursor()
        cur.execute("SELECT VERSION(), USER(), @@datadir")
        row = cur.fetchone()
        cur.execute("SHOW DATABASES")
        dbs = [r[0] for r in cur.fetchmany(10)]
        conn.close()
        return True, f"version={row[0]} user={row[1]} datadir={row[2]} dbs={dbs[:8]}"
    except Exception as exc:
        return False, str(exc)


def probe_mysql_weak(host: str, creds: list[tuple[str, str]] | None = None) -> str:
    creds = creds or [("root", ""), ("root", "root"), ("root", "toor"), ("admin", "admin")]
    greeting = _mysql_greeting(host)
    hits = []
    for user, password in creds:
        ok, detail = _try_pymysql(host, user, password)
        if ok:
            hits.append((user, password, detail))

    lines = [
        "=== MySQL weak cred probe ===",
        f"target: {host}:3306",
        f"greeting: {greeting[:120]}",
        f"tried: {len(creds)}",
        f"hits: {len(hits)}",
    ]
    if hits:
        for user, password, detail in hits:
            lines.append(f"  [+] {user}:{password!r} — {detail}")
            lines.append(f"      FOOTHOLD: mysql {user}:{password!r} — try INTO OUTFILE webshell")
        lines.append("vulnerable: True")
    else:
        if "error:" in greeting:
            lines.append("vulnerable: False")
            lines.append(f"note: port closed or filtered — {greeting}")
        else:
            lines.append("vulnerable: False")
            lines.append("note: install pymysql (pip install pymysql) for cred verification")
            lines.append("signals: mysql port open, Metasploitable often root with empty password")
    return "\n".join(lines)
