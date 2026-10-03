"""Agent help text."""


def show_help() -> str:
    return """terminator agent — commands and tools

COMMANDS
  /help       show this help
  /catalog    every attack technique + injection style
  /skills     full tool registry + technique catalog
  /findings   show saved session intel
  /clear      wipe chat memory

AUTO-RUN (direct tool output)
  run playbook on http://127.0.0.1:3000   full pipeline + skill battery
  run skill battery on http://127.0.0.1:3000   all skill checks
  check xss / sqli / ssrf / cors / idor / jwt bypass / ...
  check passive suite on http://127.0.0.1:3000
  craft sqli tautology on /user           named technique
  craft xss all variations on /search     every injection style
  craft img_onerror xss                   pick technique by name

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
  python cli.py probe --skill sqli --technique tautology
  python cli.py probe --skill xss --technique img_onerror
  python cli.py list

TAKEOVER (operator brain — intel chains, not spray)
  python cli.py takeover http://192.168.1.253
  python autorun.py --once          # autoconfig mode: takeover
  vsFTPd backdoor, WebDAV shell+exec, MySQL OUTFILE, DVWA CMDi chain
  LLM picks next move from ranked intel — one chain at a time

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
    data/reports/engagement-summary.txt lists WHICH technique worked

MODES
  python agent.py              tools-first chat
  python agent.py --tools-only never call model
  python autorun.py            fully autonomous pentest loop
  python cli.py autonomous     one-shot autonomous engagement
  python cli.py <cmd>          one-shot skill"""
