"""Agent help text."""


def show_help() -> str:
    return """terminator agent — commands and tools

COMMANDS
  /help       show this help
  /skills     list all probe + check skills
  /findings   show saved session intel
  /clear      wipe chat memory

AUTO-RUN (direct tool output)
  run playbook on http://127.0.0.1:3000   full pipeline + skill battery
  run skill battery on http://127.0.0.1:3000   all skill checks
  check xss / sqli / ssrf / cors / idor / jwt bypass / ...
  check passive suite on http://127.0.0.1:3000
  craft sqli payload for /user            skill mode (Qwen crafts payload)

SKILL GROUPS (probe_* + check_*)
  xss, sqli, redirect, traversal          injection / redirect labs
  jwt, idor, mass_assignment, rate_limit  auth labs
  cors, ssrf, crlf                        network labs
  cmdi, ssti                              injection labs
  csrf, security_headers, sensitive_leak, clickjacking, http_methods  passive

CYBORG LAB ENDPOINTS
  /search?q=  /user?id=  /redirect?url=  /files?name=
  /fetch?url=  /ping?host=  /render?template=  /echo?msg=
  /api/login  /api/profile  /api/admin  /api/cors

CLI
  python cli.py battery http://127.0.0.1:3000
  python cli.py jwt
  python cli.py probe --skill sqli --payload "' OR '1'='1"
  python cli.py list

AUTONOMOUS (no chat, no model — pentester brain)
  python autorun.py              recon -> plan skills -> execute -> report
  python autorun.py --once       one full engagement
  python autorun.py --legacy     old passive-only mode

  Adaptive — not a fixed skill script:
    1. recon + discover forms/params from HTML
    2. multiple techniques per vuln (XSS: script, img, svg… SQLi: quote, OR, union…)
    3. stops category when confirmed, escalates on partial signals
    4. auth chains: jwt none variants, mass assignment bodies, token follow-up
    5. rotates starting technique each cycle
    reports/engagement-summary.txt lists WHICH technique worked

MODES
  python agent.py              tools-first chat
  python agent.py --tools-only never call model
  python autorun.py            fully autonomous pentest loop
  python cli.py autonomous     one-shot autonomous engagement
  python cli.py <cmd>          one-shot skill"""
