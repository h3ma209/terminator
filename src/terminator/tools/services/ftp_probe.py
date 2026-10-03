"""FTP anonymous and credential probing."""

from __future__ import annotations

import ftplib
import socket


def _ftp_login(host: str, user: str, password: str, timeout: float = 8) -> tuple[bool, str]:
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, 21, timeout=timeout)
        ftp.login(user, password)
        welcome = ftp.getwelcome() or ""
        pwd = ftp.pwd()
        listing = []
        try:
            ftp.retrlines("LIST", listing.append)
        except ftplib.error_perm:
            pass
        ftp.quit()
        return True, f"login ok — pwd={pwd} — listing lines={len(listing)} — {welcome[:80]}"
    except ftplib.error_perm as exc:
        return False, f"auth failed: {exc}"
    except (OSError, socket.timeout) as exc:
        return False, f"connect error: {exc}"


def probe_ftp_anonymous(host: str) -> str:
    ok, detail = _ftp_login(host, "anonymous", "anonymous@test.com")
    lines = [
        "=== FTP anonymous ===",
        f"target: {host}:21",
        f"vulnerable: {ok}",
        f"detail: {detail}",
    ]
    if ok:
        lines.append("signals: anonymous FTP enabled, potential upload/read")
    return "\n".join(lines)


def spray_ftp_creds(host: str, creds: list[tuple[str, str]]) -> str:
    hits = []
    for user, password in creds:
        ok, detail = _ftp_login(host, user, password)
        if ok:
            hits.append((user, password, detail))
    lines = [
        "=== FTP credential spray ===",
        f"target: {host}:21",
        f"tried: {len(creds)}",
        f"hits: {len(hits)}",
    ]
    for user, password, detail in hits:
        lines.append(f"  [+] {user}:{password!r} — {detail}")
        lines.append(f"      FOOTHOLD: ftp creds {user}:{password}")
    if not hits:
        lines.append("  none")
    return "\n".join(lines)
