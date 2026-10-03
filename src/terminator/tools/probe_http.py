"""Shared HTTP helpers for security probes."""

import urllib.error
import urllib.request
from urllib.parse import urlencode

MAX_PAYLOAD_LEN = 500


def fetch_get(url: str, max_len: int = 16000, follow_redirects: bool = True) -> dict:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "terminator"})
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(
                    newurl, code, msg, headers, fp
                )
        opener = urllib.request.build_opener(NoRedirect())
        open_fn = opener.open
    else:
        open_fn = urllib.request.urlopen

    try:
        with open_fn(req, timeout=8) as res:
            body = res.read(max_len).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in res.headers.items()}
            return {
                "status": res.status,
                "body": body,
                "headers": headers,
                "url": res.geturl(),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(max_len).decode("utf-8", errors="replace") if exc.fp else ""
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return {
            "status": exc.code,
            "body": body,
            "headers": headers,
            "url": exc.geturl() if hasattr(exc, "geturl") else url,
        }
    except Exception as exc:
        return {"status": "error", "body": str(exc), "headers": {}, "url": url}


def build_get_url(base: str, path: str, param: str, value: str) -> str:
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path + "?" + urlencode({param: value})


def save_probe(skill: str, data: dict) -> None:
    from terminator.core.memory import load_findings, now, save_findings

    save_findings({
        **load_findings(),
        "target": data.get("target", ""),
        "updated": now(),
        "last_probe": {
            "skill": skill,
            **{k: v for k, v in data.items() if k != "target"},
        },
    })
