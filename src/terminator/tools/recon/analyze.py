"""Merged intel and prioritization."""

from tools.http import fetch_text, paths_to_probe, probe_path, score_probe, web_base
from tools.profile import profile_target
from tools.web import inspect_url


def analyze_target(target: str) -> str:
    base, err = web_base(target)
    if not base:
        return err
    profile = profile_target(base)
    inspect = inspect_url(base + "/")
    probes = [probe_path(base, path) for path in paths_to_probe(base)]
    ranked = []
    for probe in probes:
        score, reasons = score_probe(probe)
        if score > 0:
            ranked.append((score, probe, reasons))
    ranked.sort(key=lambda item: item[0], reverse=True)
    robots = fetch_text(base + "/robots.txt", 400)
    lines = [
        "=== merged intel ===",
        profile,
        "",
        "=== page inspect (home) ===",
        inspect,
        "",
        "=== endpoint probes ===",
    ]
    for probe in probes:
        status = probe.get("status")
        bits = [f"{probe['path']} -> {status}"]
        if probe.get("content_type"):
            bits.append(probe["content_type"])
        if probe.get("has_password"):
            bits.append("password field")
        if probe.get("is_json"):
            bits.append("json")
        lines.append("  " + " | ".join(bits))
    lines.append("")
    lines.append("=== recommended focus (priority order) ===")
    if "Disallow: /api/" in robots:
        lines.append("  note: robots.txt hides /api/ — review API auth first")
    if ranked:
        for idx, (score, probe, reasons) in enumerate(ranked[:8], start=1):
            label = ", ".join(reasons)
            lines.append(f"  {idx}. [{score}] {probe['url']} — {label}")
    else:
        lines.append("  no high-value endpoints found from probes")
    lines.append("")
    lines.append("=== lower priority / skip for now ===")
    low = [p for p in probes if score_probe(p)[0] <= 25]
    if low:
        for probe in low:
            lines.append(f"  {probe['path']} (status {probe.get('status')})")
    else:
        lines.append("  none")
    return "\n".join(lines)
