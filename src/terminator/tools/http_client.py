"""Session-aware HTTP — auth contexts, POST/JSON, scope guard."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar

from terminator.core.scope import ProgramScope, assert_in_scope


@dataclass
class HttpResponse:
    status: int | str
    body: str
    headers: dict
    url: str
    request_method: str = "GET"
    request_url: str = ""
    request_body: str = ""


@dataclass
class AuthContext:
    name: str
    username: str = ""
    password: str = ""
    token: str = ""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


class HttpSession:
    def __init__(self, scope: ProgramScope | None = None, delay_ms: int = 0) -> None:
        self.scope = scope or ProgramScope()
        self.delay_ms = delay_ms or self.scope.rate_delay_ms
        self._jar = CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._jar))
        self.default_headers = {"User-Agent": "terminator-bounty/1.0"}

    def _throttle(self) -> None:
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

    def request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | str | bytes | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
        timeout: int = 10,
        follow_redirects: bool = True,
    ) -> HttpResponse:
        err = assert_in_scope(url, self.scope)
        if err:
            return HttpResponse("blocked", err, {}, url, method, url)

        self._throttle()
        hdrs = {**self.default_headers, **(headers or {})}

        if params:
            qs = urllib.parse.urlencode(params)
            url = url + ("&" if "?" in url else "?") + qs

        body_bytes: bytes | None = None
        req_body_str = ""
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode()
            hdrs.setdefault("Content-Type", "application/json")
            req_body_str = body_bytes.decode()
        elif isinstance(data, dict):
            body_bytes = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            req_body_str = body_bytes.decode()
        elif isinstance(data, str):
            body_bytes = data.encode()
            req_body_str = data
        elif isinstance(data, bytes):
            body_bytes = data

        req = urllib.request.Request(url, data=body_bytes, method=method.upper(), headers=hdrs)
        open_fn = self._opener.open if follow_redirects else urllib.request.urlopen

        try:
            with open_fn(req, timeout=timeout) as res:
                raw = res.read(32000).decode("utf-8", errors="replace")
                rh = {k.lower(): v for k, v in res.headers.items()}
                return HttpResponse(
                    res.status, raw, rh, res.geturl(),
                    method.upper(), url, req_body_str,
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read(32000).decode("utf-8", errors="replace") if exc.fp else ""
            rh = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            return HttpResponse(
                exc.code, raw, rh,
                exc.geturl() if hasattr(exc, "geturl") else url,
                method.upper(), url, req_body_str,
            )
        except Exception as exc:
            return HttpResponse("error", str(exc), {}, url, method.upper(), url, req_body_str)

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)


def login_api(base: str, username: str, password: str, session: HttpSession) -> AuthContext:
    """Obtain token from common JSON login endpoints."""
    ctx = AuthContext(name="user", username=username, password=password)
    for path in ("/api/login", "/login", "/api/auth/login"):
        url = base.rstrip("/") + path
        for body in (
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "pass": password},
        ):
            res = session.post(url, json_body=body)
            if res.status in (200, 201):
                try:
                    data = json.loads(res.body)
                except json.JSONDecodeError:
                    continue
                token = data.get("token") or data.get("access_token") or data.get("jwt")
                if token:
                    ctx.token = str(token)
                    ctx.headers["Authorization"] = f"Bearer {token}"
                    return ctx
    return ctx


def build_contexts(base: str, auth_cfg: dict, session: HttpSession) -> dict[str, AuthContext]:
    contexts = {"anon": AuthContext(name="anon")}
    user = auth_cfg.get("username", "")
    pwd = auth_cfg.get("password", "")
    if user and pwd:
        logged = login_api(base, user, pwd, session)
        contexts["user"] = logged
        if logged.token:
            contexts["user"].headers["Authorization"] = f"Bearer {logged.token}"
    return contexts
