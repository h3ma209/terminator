"""Local tool-calling agent for Ollama (qwen2.5-coder)."""

import json
import os
import sys
from pathlib import Path

import config
from cleanup import clean_tool_output, prepare_messages
from memory_store import load_findings, load_memory, save_turn
from ollama_client import ask
from router import prefetch_data, wants_tools
from help_text import show_help
from tools.playbook import show_findings


def main() -> None:
    if len(sys.argv) > 1:
        os.chdir(sys.argv[1])
    config.ROOT = Path.cwd().resolve()

    remembered = load_memory()
    findings = load_findings()
    print(f"model: {config.MODEL}")
    print(f"workspace: {config.ROOT}")
    print(f"memory turns: {len(remembered)}")
    if findings.get("target"):
        print(f"findings: {findings['target']} ({findings.get('updated', '?')})")
    print("empty line exits, /help for commands")

    system = (
        "You are a coding assistant. Scan tools print raw reports directly. "
        "For greetings, reply in plain text. Tools: list_dir, read_file, fetch_url, "
        "scan_local, inspect_url, profile_target, analyze_target, fetch_api_routes, "
        "run_playbook, check_auth_flow, map_site, compare_runs, show_findings. "
        "Report only tool output. Do not invent data."
    )
    if findings:
        system += f"\n\nSaved findings:\n{json.dumps(findings, indent=2)[:1200]}"
    messages = [{"role": "system", "content": system}]
    messages.extend(remembered)

    while True:
        try:
            line = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            return
        if line == "/help":
            print(show_help())
            continue
        if line == "/clear":
            config.MEMORY_PATH.unlink(missing_ok=True)
            messages[:] = [messages[0]]
            print("memory cleared")
            continue
        if line == "/findings":
            print(show_findings())
            continue

        messages.append({"role": "user", "content": line})
        prefetch = prefetch_data(line)
        if prefetch:
            tool_name, raw = prefetch
            answer = clean_tool_output(tool_name, raw)
            print(f"\n[tool] {tool_name} (auto)")
            print(answer)
        else:
            answer = ask(messages, wants_tools(line))
            print(answer)
        save_turn("user", line)
        save_turn("assistant", answer)
        messages[:] = prepare_messages(messages)


if __name__ == "__main__":
    main()
