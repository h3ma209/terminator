"""Parse tool calls from model text."""

import json


def calls_from_text(content: str) -> list:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict) and "name" in data:
        data = [data]
    if not isinstance(data, list):
        return []
    calls = []
    for item in data:
        if isinstance(item, dict) and item.get("name"):
            calls.append({"function": {"name": item["name"], "arguments": item.get("arguments") or {}}})
    return calls
