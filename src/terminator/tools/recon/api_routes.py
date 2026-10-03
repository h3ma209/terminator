"""API route discovery."""

import re

from terminator import config
from terminator.tools.http import fetch_text, request_method, web_base


def discover_api_paths(base: str) -> list[str]:
    paths = set(config.API_CANDIDATES)
    robots = fetch_text(base + "/robots.txt", 400)
    for line in robots.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            entry = line.split(":", 1)[1].strip()
            if "/api" in entry:
                paths.add(entry.rstrip("/") if entry != "/api/" else "/api")
    for page in ("/", "/profile.html"):
        text = fetch_text(base + page, 6000)
        if text.startswith("error:"):
            continue
        body = text.split("\n", 1)[-1] if text.startswith("status ") else text
        for match in re.finditer(r'["\'](/api/[a-zA-Z0-9_./-]+)["\']', body):
            paths.add(match.group(1))
        for match in re.finditer(r'fetch\s*\(\s*["\'](/api/[^"\']+)["\']', body, flags=re.I):
            paths.add(match.group(1))
    return sorted(paths)


def fetch_api_routes(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    paths = discover_api_paths(base)
    lines = [f"base: {base}", f"candidate paths: {len(paths)}", ""]
    found = []
    for path in paths:
        url = base.rstrip("/") + path
        get = request_method(url, "GET")
        opt = request_method(url, "OPTIONS")
        post = request_method(url, "POST", b"{}")
        statuses = {get.get("status"), opt.get("status"), post.get("status")}
        if statuses <= {"error", 404} or statuses == {404}:
            continue
        found.append(path)
        lines.append(path)
        lines.append(f"  GET {get.get('status')} {get.get('content_type', '')}")
        if get.get("body"):
            lines.append(f"    {get['body'][:200]}")
        if opt.get("allow"):
            lines.append(f"  OPTIONS Allow: {opt['allow']}")
        elif opt.get("status") not in {404, "error"}:
            lines.append(f"  OPTIONS {opt.get('status')}")
        if post.get("status") not in {404, "error"} and post.get("status") != get.get("status"):
            lines.append(f"  POST {post.get('status')} {post.get('content_type', '')}")
            if post.get("body"):
                lines.append(f"    {post['body'][:200]}")
        if path.startswith("/api") and post.get("status") in {200, 400, 401, 403, 405}:
            lines.append("  note: accepts POST")
        if get.get("status") in {401, 403}:
            lines.append("  note: auth required on GET")
        lines.append("")
    if not found:
        lines.append("no API routes responded (non-404)")
    else:
        lines.append(f"active routes: {len(found)}")
    return "\n".join(lines).strip()
