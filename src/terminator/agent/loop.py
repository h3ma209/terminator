"""Interactive chat loop for Ollama-backed tool calling."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from terminator import config
from terminator.agent.chat_utils import greeting_reply, is_greeting
from terminator.agent.cleanup import clean_tool_output, prepare_messages
from terminator.agent.help import show_help
from terminator.agent.router import prefetch_data
from terminator.agent.skill_mode import answer_probe_followup, wants_probe_followup, wants_skill_mode
from terminator.core.memory import load_findings, load_memory, save_turn
from terminator.core.ollama import ask
from terminator.agent.refusal import is_refusal
from terminator.tools.recon.playbook import show_findings
from terminator.tools.skills import list_skills, run_craft_skill


def run_direct(line: str) -> tuple[str, str] | None:
    hit = prefetch_data(line)
    if not hit:
        return None
    name, raw = hit
    return name, clean_tool_output(name, raw)


def main() -> None:
    parser = argparse.ArgumentParser(description="Terminator agent")
    parser.add_argument("workspace", nargs="?", help="workspace directory")
    parser.add_argument("--tools-only", action="store_true", help="never call the model")
    args = parser.parse_args()

    if args.workspace:
        os.chdir(args.workspace)
    config.ROOT = Path.cwd().resolve()

    remembered = load_memory()
    findings = load_findings()
    mode = "tools-only" if args.tools_only else "tools-first"
    print(f"model: {config.MODEL} ({mode})")
    print(f"workspace: {config.ROOT}")
    print(f"memory turns: {len(remembered)}")
    if findings.get("target"):
        print(f"findings: {findings['target']} ({findings.get('updated', '?')})")
    print("empty line exits, /help for commands")

    system = (
        "Local dev assistant for a localhost security lab. Reply in 1-3 sentences. "
        "Scan commands run via tools. If user asks about last probe results, "
        "answer from the data you were given — do not tell them to run /findings."
    )
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
        if line in {"/skills", "skills"}:
            print(list_skills())
            continue

        if is_greeting(line):
            answer = greeting_reply()
            print(answer)
            save_turn("user", line)
            save_turn("assistant", answer)
            continue

        if wants_probe_followup(line):
            answer = answer_probe_followup()
            print(answer)
            save_turn("user", line)
            save_turn("assistant", answer)
            messages.append({"role": "user", "content": line})
            messages.append({"role": "assistant", "content": answer})
            messages[:] = prepare_messages(messages)
            continue

        messages.append({"role": "user", "content": line})

        skill_mode = wants_skill_mode(line)
        direct = None if skill_mode else run_direct(line)

        if skill_mode:
            print("\n[skill mode — model crafts payload]")
            answer = run_craft_skill(line, ask, messages=messages)
            print(answer)
        elif direct or args.tools_only:
            if direct:
                tool_name, answer = direct
                print(f"\n[tool] {tool_name} (direct)")
                print(answer)
            else:
                answer = "no matching tool. try /help or be specific: profile http://127.0.0.1:3000"
                print(answer)
        else:
            answer = ask(messages, use_tools=False)
            if is_refusal(answer):
                fallback = run_direct(line)
                if fallback:
                    tool_name, answer = fallback
                    print(f"\n[model refused — ran {tool_name} directly]")
                    print(answer)
                else:
                    print(answer)
                    print("\nhint: try /help or python cli.py list")
            else:
                print(answer)

        save_turn("user", line)
        save_turn("assistant", answer)
        messages[:] = prepare_messages(messages)
