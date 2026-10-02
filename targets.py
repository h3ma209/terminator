"""Target URL extraction from user text."""

import re


def extract_url(text: str) -> str:
    match = re.search(r"https?://[^\s'\"<>]+", text, flags=re.I)
    if match:
        return match.group(0).rstrip(".,)")
    if re.search(r"127\.0\.0\.1|localhost", text, flags=re.I):
        return "http://127.0.0.1:3000"
    return "http://127.0.0.1:3000"
