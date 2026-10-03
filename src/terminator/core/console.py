"""Terminal output — colors, emojis, readable live logs + final reports."""

from __future__ import annotations

import re
import sys
from typing import Callable

# ── ANSI ──────────────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "gray": "\033[90m",
}

_SEVERITY_STYLE = {
    "critical": ("red", "🔥"),
    "high": ("yellow", "⚠️"),
    "medium": ("blue", "ℹ️"),
    "low": ("gray", "·"),
    "info": ("gray", "·"),
}

_ACCESS_STYLE = {
    "root": ("green", "👑 ROOT"),
    "shell": ("green", "🐚 SHELL"),
    "user": ("yellow", "👤 USER"),
    "none": ("gray", "— none"),
}

_TAG_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"^\[operator\]", re.I), "red", "🎯", "OPERATOR"),
    (re.compile(r"^\[recon\]", re.I), "cyan", "🔍", "RECON"),
    (re.compile(r"^\[brain\]", re.I), "magenta", "🧠", "BRAIN"),
    (re.compile(r"^\[bounty\]", re.I), "yellow", "💰", "BOUNTY"),
    (re.compile(r"^\[chain\]", re.I), "blue", "⛓️", "CHAIN"),
    (re.compile(r"^\[passive\]", re.I), "gray", "🛡️", "PASSIVE"),
    (re.compile(r"^\[attack\]", re.I), "magenta", "⚔️", "ATTACK"),
    (re.compile(r"^\[analyze\]", re.I), "cyan", "📊", "ANALYZE"),
]

_PLAIN_RE = re.compile(r"\033\[[0-9;]*m")


def _enable_windows_ansi() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def strip_ansi(text: str) -> str:
    return _PLAIN_RE.sub("", text)


def _c(color: str, text: str, *, bold: bool = False, dim: bool = False) -> str:
    parts = []
    if bold:
        parts.append(_BOLD)
    if dim:
        parts.append(_DIM)
    parts.append(_COLORS.get(color, ""))
    parts.append(text)
    parts.append(_RESET)
    return "".join(parts)


class Console:
    """Pretty terminal output. Use `.log` as log_fn during engagements."""

    def __init__(self, *, color: bool | None = None, emoji: bool = True) -> None:
        if color is None:
            color = sys.stdout.isatty()
        self.color = color
        self.emoji = emoji
        if self.color:
            _enable_windows_ansi()

    # ── primitives ────────────────────────────────────────────────────────────

    def write(self, text: str, *, plain_file: Callable[[str], None] | None = None) -> None:
        line = text if text.endswith("\n") else text + "\n"
        sys.stdout.buffer.write(line.encode("utf-8", errors="replace"))
        if plain_file:
            plain_file(strip_ansi(line.rstrip("\n")))

    def blank(self) -> None:
        self.write("")

    def rule(self, title: str = "", char: str = "─", width: int = 60) -> None:
        if not title:
            line = char * width
        else:
            pad = max(2, (width - len(title) - 2) // 2)
            line = f"{char * pad} {title} {char * pad}"
        self.write(self._style_line(line, "cyan", bold=True))

    def banner(self, mode: str, target: str) -> None:
        self.blank()
        self.rule()
        icon = {"takeover": "🎯", "bounty": "💰", "autonomous": "🤖"}.get(mode, "⚡")
        title = f"{icon} TERMINATOR — {mode.upper()}" if self.emoji else f"TERMINATOR — {mode.upper()}"
        self.write(self._style_line(title, "cyan", bold=True))
        self.write(self._style_line(f"   target → {target}", "white"))
        self.rule()
        self.blank()

    def _style_line(self, text: str, color: str, *, bold: bool = False, dim: bool = False) -> str:
        if not self.color:
            return text
        return _c(color, text, bold=bold, dim=dim)

    # ── live log (log_fn) ─────────────────────────────────────────────────────

    def log(self, msg: str) -> None:
        """Drop-in replacement for print during engagements."""
        if not msg:
            self.blank()
            return

        for line in msg.splitlines():
            self.write(self._format_log_line(line))

    def _format_log_line(self, line: str) -> str:
        stripped = line.strip()

        # Section headers from intel formatters
        if stripped.startswith("===") and stripped.endswith("==="):
            inner = stripped.strip("= ").strip()
            return self._style_line(f"\n{'─' * 50}\n📋 {inner}\n{'─' * 50}", "cyan", bold=True)

        # Numbered ops: "1. [ROOT|stealth:high] vsftpd..."
        m = re.match(r"^\s*(\d+)\.\s+\[([^\]]+)\]\s+(\S+)", line)
        if m:
            num, tags, op_id = m.groups()
            impact = tags.split("|")[0] if "|" in tags else tags
            sev_key = impact.lower().split(":")[0]
            _, icon = _SEVERITY_STYLE.get(sev_key, ("white", "•"))
            if not self.emoji:
                icon = {"root": "*", "shell": "!", "high": "!", "medium": "-", "low": "."}.get(sev_key, "•")
            head = f"  {icon} {num}. {_c('white', op_id, bold=True)}" if self.color else f"  {icon} {num}. {op_id}"
            if self.color:
                return head + _DIM + f"  [{tags}]" + _RESET
            return f"  {icon} {num}. {op_id}  [{tags}]"

        # Sub-lines: title / why
        if re.match(r"^\s+why:", line, re.I):
            body = re.split(r"why:", line, flags=re.I)[-1].strip()
            prefix = "     💡 " if self.emoji else "     → "
            return prefix + self._style_line(body, "gray", dim=True)
        if re.match(r"^\s{3,}\S", line) and "why:" not in line.lower():
            return "   " + self._style_line(line.strip(), "gray", dim=True)

        # Victory
        if line.strip().startswith("[win]"):
            body = line.replace("[win]", "").strip()
            return self._style_line(f"🏆 WIN — {body}", "green", bold=True)

        # Result markers
        if "[+] CONFIRMED" in line or line.strip().startswith("[+]"):
            body = line.replace("[+]", "").strip()
            icon = "✅ " if self.emoji else "+ "
            return icon + self._style_line(body, "green", bold=True)
        if "[~]" in line:
            body = line.replace("[~]", "").strip()
            icon = "🟡 " if self.emoji else "~ "
            return icon + self._style_line(body, "yellow")
        if "[-]" in line or "no hit" in line.lower():
            body = line.replace("[-]", "").strip()
            icon = "⬜ " if self.emoji else "- "
            return icon + self._style_line(body, "gray", dim=True)

        # Tagged lines: [brain] step 1 -> foo
        for pat, color, emoji, label in _TAG_RULES:
            if pat.search(line):
                body = pat.sub("", line).strip()
                prefix = f"{emoji} {_c(color, label, bold=True)} " if self.color and self.emoji else f"[{label}] "
                if "step" in body.lower() and "->" in body:
                    parts = body.split("->", 1)
                    left = parts[0].strip()
                    right = parts[1].strip() if len(parts) > 1 else ""
                    action = self._style_line(right, "white", bold=True) if self.color else right
                    return f"{prefix}{left} → {action}"
                if body.lower().startswith("why:"):
                    return prefix + self._style_line(body, "gray", dim=True)
                return prefix + self._style_line(body, "white")

        # Indented detail
        if line.startswith("  ") and not line.startswith("   "):
            return "  " + self._style_line(line.strip(), "gray", dim=True)

        return line

    # ── final report ──────────────────────────────────────────────────────────

    def print_report(self, report: str) -> None:
        """Render the engagement report with structure + color."""
        self.blank()
        self.rule("REPORT")
        self.blank()
        for line in report.splitlines():
            styled = self._format_report_line(line)
            if styled:
                self.write(styled)
        self.blank()
        self.rule("END")
        self.blank()

    def victory(self, access: str, chain: str, proof: str = "") -> None:
        """Big win banner after live engagement."""
        icons = {"root": "👑", "shell": "🐚", "user": "👤"}
        icon = icons.get(access, "✅")
        self.blank()
        self.write(self._style_line(f"{icon}  {access.upper()} — via {chain}", "green", bold=True))
        if proof:
            self.write(self._style_line(f"   proof: {proof[:120]}", "green"))
        self.blank()

    def _format_report_line(self, line: str) -> str:
        s = line.strip()

        if s.startswith("=== ") and s.endswith(" ==="):
            title = s.strip("= ").strip()
            icons = {
                "OPERATOR TAKEOVER REPORT": "🎯",
                "BOUNTY HUNTER REPORT": "💰",
                "SUBMISSION-READY FINDINGS": "📤",
                "SUBMISSION EXPORT": "📁",
                "CONFIRMED CHAINS": "⛓️",
                "WHAT HAPPENED": "🧠",
                "OPEN SERVICES": "🔌",
                "NEXT STEPS": "➡️",
                "OPERATOR TRACE": "🧠",
                "BOUNTY TRACE": "🧠",
                "STRATEGIC PLAN": "📋",
                "OPERATOR MINDSET": "💭",
                "recon excerpt": "🔍",
            }
            icon = "📋"
            for key, em in icons.items():
                if key.lower() in title.lower():
                    icon = em
                    break
            bar = "═" * 52
            head = f"\n{bar}\n{icon}  {title}\n{bar}" if self.emoji else f"\n{bar}\n{title}\n{bar}"
            return self._style_line(head, "cyan", bold=True)

        if s.startswith("access level:"):
            level = s.split(":", 1)[-1].strip().lower()
            color, label = _ACCESS_STYLE.get(level, ("white", level.upper()))
            text = f"Access: {label}" if self.emoji else f"Access: {level.upper()}"
            return self._style_line(text, color, bold=True)

        if s.startswith("impact level:"):
            level = s.split(":", 1)[-1].strip().lower()
            color, icon = _SEVERITY_STYLE.get(level, ("white", "•"))
            text = f"{icon} Impact: {level.upper()}" if self.emoji else f"Impact: {level.upper()}"
            return self._style_line(text, color, bold=True)

        if s.startswith("assessment:"):
            body = s.split(":", 1)[-1].strip()
            if "ROOT" in body:
                return self._style_line(f"🏆 {s}", "green", bold=True)
            if "SHELL" in body:
                return self._style_line(f"🐚 {s}", "green", bold=True)
            return self._style_line(f"📊 {s}", "yellow")

        m = re.match(r"^\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.I)
        if m:
            sev = m.group(1).lower()
            color, icon = _SEVERITY_STYLE.get(sev, ("white", "•"))
            rest = line[m.end():].strip()
            prefix = f"  {icon} " if self.emoji else "  "
            tag = self._style_line(f"[{m.group(1).upper()}]", color, bold=True) if self.color else f"[{m.group(1).upper()}]"
            return prefix + tag + " " + rest

        if s.startswith("target:") or s.startswith("host:"):
            return self._style_line(f"🎯 {s}", "white")
        if s.startswith("confirmed findings:"):
            return self._style_line(f"🔎 {s}", "white", bold=True)
        if s.startswith("chains executed:"):
            return self._style_line(f"⛓️ {s}", "white")
        if s.startswith("markdown:"):
            return self._style_line(f"📄 {s}", "blue")
        if s.startswith("snapshot:") or s.startswith("full log:"):
            return self._style_line(f"📁 {s}", "gray", dim=True)
        if re.match(r"^\s+\d+/", s):
            return self._style_line(f"  🔌 {s.strip()}", "white")
        if s.startswith("=== step ") or s.startswith("reason:"):
            return self._style_line(s, "magenta") if s.startswith("=== step ") else "  " + self._style_line(f"💡 {s}", "gray", dim=True)
        if s.startswith("=== chain:"):
            return self._style_line(f"⛓️  {s.strip('= ')}", "blue", bold=True)
        if s in ("vulnerable: True", "vulnerable: False"):
            ok = "True" in s
            icon = "✅" if ok else "⬜"
            return self._style_line(f"  {icon} {s}", "green" if ok else "gray")
        if s.startswith("FOOTHOLD:"):
            return self._style_line(f"  🏁 {s}", "green", bold=True)
        if s.startswith("proof:"):
            return "    " + self._style_line(f"🔬 {s}", "green")
        if s.startswith("path:"):
            return "    " + self._style_line(s, "gray", dim=True)
        if s.startswith("why:"):
            return "    " + self._style_line(f"💡 {s}", "gray", dim=True)

        if not s:
            return ""
        return line


def make_logger(
    *,
    color: bool | None = None,
    emoji: bool = True,
    plain_sink: Callable[[str], None] | None = None,
) -> tuple[Console, Callable[[str], None]]:
    """Return (console, log_fn). Optional plain_sink for log files."""
    console = Console(color=color, emoji=emoji)
    if plain_sink:
        def log_fn(msg: str) -> None:
            for line in msg.splitlines() or [""]:
                plain_sink(strip_ansi(console._format_log_line(line)))
            console.log(msg)
        return console, log_fn
    return console, console.log
