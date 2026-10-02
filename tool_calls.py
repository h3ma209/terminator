"""Parse tool calls from model text."""

import json
import re


def _parse_args(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def _load_json_object(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        return None
    blob = match.group(0)
    for _ in range(3):
        try:
            data = json.loads(blob)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            blob = blob[:-1]
    return None


def calls_from_text(content: str) -> list:
    if not content:
        return []
    calls = []
    seen = set()

    def add(item: dict) -> None:
        name = item.get("name")
        if not name:
            return
        key = (name, json.dumps(_parse_args(item.get("arguments") or {}), sort_keys=True))
        if key in seen:
            return
        seen.add(key)
        calls.append({"function": {"name": name, "arguments": _parse_args(item.get("arguments") or {})}})

    for block in re.finditer(r"<tool>\s*(.*?)\s*</tool>", content, flags=re.I | re.S):
        data = _load_json_object(block.group(1))
        if data and data.get("name"):
            add(data)

    data = _load_json_object(content.strip())
    if data is None:
        return calls
    if isinstance(data, dict) and data.get("name"):
        add(data)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                add(item)
    return calls
