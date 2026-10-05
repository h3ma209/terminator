"""Structured LLM client — JSON, budget, cache, graceful fallback."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field


@dataclass
class LLMBudget:
    max_calls: int = 40
    max_tokens: int = 80_000
    calls: int = 0
    tokens: int = 0

    def can_spend(self, est_tokens: int = 800) -> bool:
        return self.calls < self.max_calls and (self.tokens + est_tokens) <= self.max_tokens

    def spend(self, text: str) -> None:
        self.calls += 1
        self.tokens += max(len(text) // 4, 100)


_CACHE: dict[str, str] = {}
last_error: str = ""


def _cache_key(role: str, user: str) -> str:
    blob = f"{role}\n{user}"
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if fence:
        text = fence.group(1).strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, flags=re.S)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return None


def ask_text(
    system: str,
    user: str,
    *,
    budget: LLMBudget | None = None,
    use_cache: bool = True,
) -> str | None:
    """Return assistant text or None if LLM unavailable / budget exhausted."""
    from terminator import config
    if config.STUB_LLM:
        return None
    if budget and not budget.can_spend():
        return None
    key = _cache_key(system, user)
    if use_cache and key in _CACHE:
        return _CACHE[key]
    global last_error
    try:
        from terminator.core.ollama import chat
        data = chat([
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ], use_tools=False)
        text = (data.get("message") or {}).get("content") or ""
        if budget:
            budget.spend(text + user)
        if use_cache and text:
            _CACHE[key] = text
        last_error = ""
        return text
    except (SystemExit, Exception) as exc:
        last_error = str(exc)
        return None


def ask_json(
    system: str,
    user: str,
    *,
    schema_hint: str = "",
    budget: LLMBudget | None = None,
    retries: int = 2,
) -> dict | None:
    """Ask for JSON; repair once if parse fails."""
    hint = f"\nReply JSON only. Schema: {schema_hint}" if schema_hint else "\nReply JSON only."
    full_system = system + hint
    for attempt in range(retries):
        text = ask_text(full_system, user, budget=budget, use_cache=(attempt == 0))
        if not text:
            return None
        obj = _extract_json(text)
        if obj is not None:
            return obj
        if attempt < retries - 1:
            user = user + "\n\nYour last reply was not valid JSON. Reply with JSON only."
    return None


def clear_cache() -> None:
    _CACHE.clear()
