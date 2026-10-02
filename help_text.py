"""Agent help text."""


def show_help() -> str:
    return """terminator agent — commands and tools

COMMANDS
  /help       show this help
  /skills     list agent skills + params (model can craft values)
  /findings   show saved session intel (findings.json)
  /clear      wipe chat memory (memory.jsonl)
  (empty line) exit

AUTO-RUN (prints raw tool output, no model rewrite)
  run playbook on http://127.0.0.1:3000   full scan pipeline + snapshot
  profile http://127.0.0.1:3000           ports, headers, robots.txt, sitemap
  analyze http://127.0.0.1:3000           merge scans + priority targets
  fetch api routes on http://127.0.0.1:3000   discover API endpoints
  check auth flow on http://127.0.0.1:3000    login + JWT test (demo/demo)
  map site http://127.0.0.1:3000          crawl pages from sitemap/links
  check xss on http://127.0.0.1:3000      auto XSS scan (fixed payloads)
  craft xss payload for /search           skill mode — Qwen picks payload, runs probe_xss
  compare runs                            diff last two snapshots
  inspect http://127.0.0.1:3000           passive URL security review
  scan http://127.0.0.1:3000              localhost header check

TOOLS (model can call these on other prompts)
  list_dir / read_file    workspace files
  fetch_url               GET any http/https URL
  scan_local              header check (localhost only)
  inspect_url             headers, cookies, TLS, forms (any URL)
  profile_target          full localhost profile
  analyze_target          merged intel + focus ranking
  fetch_api_routes        probe API paths
  run_playbook            all of the above in one run
  check_auth_flow         JWT login flow test
  map_site                site structure map
  check_xss               auto XSS scan; optional payload/path/param args
  probe_xss               one param + model-crafted payload
  list_skills             skill catalog with param docs
  compare_runs            snapshot diff
  show_findings           structured session notes

AUTOMATE (no chat, no model)
  python cli.py playbook http://127.0.0.1:3000     one-shot manual

FULL AUTO (runs alone on a timer)
  python autorun.py              passive loop (profile, api, map)
  python autorun.py --once       one cycle then exit
  python autorun.py --full       include auth + analyze every cycle

  autoconfig.json:
    interval_seconds   min 60 (default 3600)
    steps              profile, api, map (passive)
    auth_every_cycles  login test every N cycles (default 12)

  Logs: autorun.log | Latest: reports/latest.txt

  Start at Windows login (Task Scheduler):
    python E:\\terminator\\autorun.py

MODES
  python agent.py              tools-first (model only for chat)
  python agent.py --tools-only never call model — no refusals
  python autorun.py            fully automatic on timer
  python cli.py list           one-shot commands

NOTES
  Default model: thirdeyeai/Qwen2.5-Coder-7B-Instruct-Uncensored:Q4_0
  Override: set OLLAMA_MODEL=... | Use --tools-only to skip model entirely"""
