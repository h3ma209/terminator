"""Context cleanup before sending data to the model."""

import re

import config
from tool_calls import calls_from_text


def strip_html(html: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", html)
    text = re.sub(r"(?is)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def summarize_fetch(content: str) -> str:
    lines = content.splitlines()
    if not lines or not lines[0].startswith("status "):
        return content
    status = lines[0]
    body = "\n".join(lines[1:])
    title = re.search(r"(?is)<title[^>]*>([^<]+)", body)
    title_bit = f" title={title.group(1).strip()}" if title else ""
    if "<html" in body.lower() or "<!doctype" in body.lower():
        plain = strip_html(body)[: config.FETCH_BODY_MAX]
        return f"{status}{title_bit}\ntext: {plain or '(empty)'}"
    return f"{status}\n{body[: config.FETCH_BODY_MAX]}"


def clean_text(text: str, limit: int = config.TOOL_OUTPUT_MAX) -> str:
    if not text:
        return ""
    text = text.replace("\x00", "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if "\n" in cut[-300:]:
        cut = cut[: cut.rfind("\n")]
    return cut.rstrip() + "\n...[truncated]"


def clean_tool_output(tool: str, content: str) -> str:
    if tool == "fetch_url":
        return clean_text(summarize_fetch(content), config.TOOL_OUTPUT_MAX)
    if tool in config.AUTO_TOOLS:
        return clean_text(content, config.TOOL_OUTPUT_MAX * 3)
    if tool == "read_file" and content.count("\n") > config.FILE_HEAD_LINES:
        lines = content.splitlines()
        head = "\n".join(lines[: config.FILE_HEAD_LINES])
        return clean_text(f"{head}\n...[file truncated, {len(lines)} lines total]", config.TOOL_OUTPUT_MAX)
    return clean_text(content, config.TOOL_OUTPUT_MAX)


def prepare_messages(messages: list) -> list:
    if not messages:
        return []
    system = [messages[0]] if messages and messages[0].get("role") == "system" else []
    rest = messages[len(system):]
    kept = []
    users = 0
    for msg in reversed(rest):
        kept.append(msg)
        if msg.get("role") == "user":
            users += 1
            if users > config.CONTEXT_TURNS:
                break
    kept.reverse()
    out = list(system)
    for msg in kept:
        role = msg.get("role")
        content = msg.get("content") or ""
        if role == "tool":
            out.append({"role": "tool", "content": clean_text(content, config.TOOL_OUTPUT_MAX)})
            continue
        if role == "assistant":
            item = {"role": "assistant", "content": clean_text(content, config.TOOL_OUTPUT_MAX)}
            if msg.get("tool_calls"):
                item["tool_calls"] = msg["tool_calls"]
            elif calls_from_text(content):
                item["content"] = "[called tools]"
            out.append(item)
            continue
        if role == "user":
            out.append({"role": "user", "content": clean_text(content, config.MEMORY_CHARS)})
    return out
