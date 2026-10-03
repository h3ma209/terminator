"""Mine params/endpoints from HTML, forms, API discovery."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from terminator.tools.http_client import HttpSession


@dataclass
class Endpoint:
    path: str
    method: str
    params: list[str]
    content_type: str
    source: str
    has_auth: bool = False


def _norm_path(path: str) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path


def mine_forms(html: str, page_path: str) -> list[Endpoint]:
    eps: list[Endpoint] = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.I | re.S):
        attrs, inner = match.group(1), match.group(2)
        method = "GET"
        m = re.search(r'method=["\']([^"\']+)', attrs, flags=re.I)
        if m:
            method = m.group(1).strip().upper()
        action = page_path
        a = re.search(r'action=["\']([^"\']*)', attrs, flags=re.I)
        if a and a.group(1).strip():
            action = _norm_path(a.group(1))
        params = []
        for inp in re.finditer(r"<(input|textarea|select)\b([^>]*)>", inner, flags=re.I):
            tag = inp.group(2)
            itype = re.search(r'type=["\']([^"\']+)', tag, flags=re.I)
            if itype and itype.group(1).lower() in {"submit", "button", "image", "reset"}:
                continue
            name = re.search(r'name=["\']([^"\']+)', tag, flags=re.I)
            if name:
                params.append(name.group(1))
        if params:
            eps.append(Endpoint(action, method, params, "form", f"form on {page_path}"))
    return eps


def mine_links(html: str) -> list[str]:
    paths = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, flags=re.I):
        href = m.group(1)
        if href.startswith("/") and not href.startswith("//"):
            paths.add(_norm_path(href))
    for m in re.finditer(r'["\'](/api/[^"\']+)["\']', html):
        paths.add(_norm_path(m.group(1)))
    return sorted(paths)


def mine_page(session: HttpSession, base: str, path: str) -> tuple[str, list[Endpoint], list[str]]:
    url = base.rstrip("/") + path
    res = session.get(url)
    if res.status == "blocked":
        return res.body, [], []
    eps = mine_forms(res.body, _norm_path(path))
    links = mine_links(res.body)
    return res.body, eps, links


def discover_endpoints(base: str, paths: list[str], session: HttpSession | None = None) -> list[Endpoint]:
    session = session or HttpSession()
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    out: list[Endpoint] = []

    def add(ep: Endpoint) -> None:
        key = (ep.method, ep.path, tuple(sorted(ep.params)))
        if key in seen:
            return
        seen.add(key)
        out.append(ep)

    for path in paths:
        _, eps, links = mine_page(session, base, path)
        for ep in eps:
            add(ep)
        for link in links:
            add(Endpoint(link, "GET", [], "link", f"discovered link from {path}"))

    # JSON API hints from openapi-ish paths
    for hint in ("/openapi.json", "/swagger.json", "/api/docs"):
        res = session.get(base.rstrip("/") + hint)
        if res.status != 200:
            continue
        try:
            spec = json.loads(res.body)
        except json.JSONDecodeError:
            continue
        for route, methods in (spec.get("paths") or {}).items():
            for meth, detail in methods.items():
                if meth.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                params = [p.get("name", "") for p in detail.get("parameters") or [] if p.get("name")]
                add(Endpoint(_norm_path(route), meth.upper(), params, "openapi", f"openapi {hint}"))

    return out
