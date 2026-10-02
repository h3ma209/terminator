"""Agent help text."""


def show_help() -> str:
    return """terminator agent — commands and tools

COMMANDS
  /help       show this help
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
  compare_runs            snapshot diff
  show_findings           structured session notes

NOTES
  Scan tools only target 127.0.0.1 / localhost unless noted.
  Reports save to findings.json and reports/
  Model: qwen2.5-coder via Ollama (127.0.0.1:11434)"""
