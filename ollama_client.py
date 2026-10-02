"""Ollama chat loop and tool execution."""

import json
import sys
import urllib.error
import urllib.request

import config
from cleanup import clean_text, clean_tool_output, prepare_messages
from tool_calls import calls_from_text
from tools import HANDLERS, TOOLS


def chat(messages: list, use_tools: bool) -> dict:
    payload = {"model": config.MODEL, "messages": prepare_messages(messages), "stream": False}
    if use_tools:
        payload["tools"] = TOOLS
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{config.HOST}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as res:
            return json.load(res)
    except urllib.error.URLError as exc:
        raise SystemExit(f"ollama unreachable at {config.HOST}: {exc}") from exc


def run_tools(message: dict) -> list:
    calls = message.get("tool_calls") or calls_from_text(message.get("content") or "")
    results = []
    for call in calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        raw = fn.get("arguments") or {}
        args = json.loads(raw) if isinstance(raw, str) else raw
        handler = HANDLERS.get(name)
        if handler is None:
            content = f"unknown tool: {name}"
        else:
            try:
                content = handler(**args)
            except Exception as exc:
                content = f"error: {exc}"
        print(f"\n[tool] {name} {args}")
        results.append({"role": "tool", "content": clean_tool_output(name, content)})
    return results


def ask(messages: list, use_tools: bool) -> str:
    seen = set()
    for _ in range(config.MAX_STEPS):
        data = chat(messages, use_tools)
        message = data.get("message") or {}
        calls = message.get("tool_calls") or calls_from_text(message.get("content") or "")
        if not calls:
            reply = clean_text(message.get("content") or "", config.TOOL_OUTPUT_MAX)
            message["content"] = reply
            messages.append(message)
            return reply
        fresh = []
        for call in calls:
            fn = call.get("function") or {}
            key = (fn.get("name"), json.dumps(fn.get("arguments") or {}, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            fresh.append(call)
        if not fresh:
            use_tools = False
            messages.append({
                "role": "user",
                "content": "Tools already ran. Reply in plain text. Do not call tools.",
            })
            continue
        message["tool_calls"] = fresh
        messages.append(message)
        messages.extend(run_tools(message))
    return "stopped: too many tool steps"
