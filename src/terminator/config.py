"""Shared configuration and paths."""

from pathlib import Path

HOST = __import__("os").environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = __import__("os").environ.get(
    "OLLAMA_MODEL", "huihui_ai/qwen2.5-coder-abliterate:14b"
)
MAX_STEPS = 8
LLM_BUDGET_CALLS = int(__import__("os").environ.get("TERMINATOR_LLM_CALLS", "60"))
LLM_BUDGET_TOKENS = int(__import__("os").environ.get("TERMINATOR_LLM_TOKENS", "80000"))
SKIP_BROWSER = __import__("os").environ.get("TERMINATOR_SKIP_BROWSER", "").lower() in {"1", "true", "yes"}
STUB_LLM = __import__("os").environ.get("TERMINATOR_STUB_LLM", "").lower() in {"1", "true", "yes"}
MAX_READ = 32_000
MEMORY_TURNS = 12
MEMORY_CHARS = 400
CONTEXT_TURNS = 6
TOOL_OUTPUT_MAX = 1800
FETCH_BODY_MAX = 500
FILE_HEAD_LINES = 60

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ROOT = Path.cwd().resolve()

MEMORY_PATH = DATA_DIR / "memory.jsonl"
FINDINGS_PATH = DATA_DIR / "findings.json"
REPORTS_DIR = DATA_DIR / "reports"
AUTOCONFIG_PATH = PROJECT_ROOT / "autoconfig.json"
LOG_PATH = DATA_DIR / "autorun.log"

# backward compat for code that referenced AGENT_DIR
AGENT_DIR = PROJECT_ROOT
ALLOW_LAN = False

AUTO_TOOLS = frozenset({
    "profile_target", "analyze_target", "fetch_api_routes",
    "run_playbook", "check_auth_flow", "check_login_apis", "map_site",
    "compare_runs", "show_findings", "list_skills", "run_skill", "run_skill_battery",
    "check_xss", "probe_xss", "check_sqli", "probe_sqli",
    "check_redirect", "probe_redirect", "check_traversal", "probe_traversal",
    "check_auth_bypass", "probe_jwt", "check_idor", "probe_idor",
    "probe_mass_assignment", "check_rate_limit",
    "check_cors", "probe_cors", "check_ssrf", "probe_ssrf", "check_crlf", "probe_crlf",
    "check_cmdi", "probe_cmdi", "check_ssti", "probe_ssti",
    "check_csrf", "check_security_headers", "check_sensitive_leak",
    "check_clickjacking", "check_http_methods", "run_passive_suite",
    "run_autonomous_engagement",
})

SKIP_DIRS = frozenset({"__pycache__", ".git", ".venv", "venv", "src", "data"})

HEADER_CHECKS = (
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy",
    "x-frame-options",
    "strict-transport-security",
    "permissions-policy",
)

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    80: "http",
    443: "https",
    3000: "http-dev",
    3306: "mysql",
    5000: "dev",
    5432: "postgres",
    6379: "redis",
    8000: "dev",
    8080: "http-alt",
    11434: "ollama",
    27017: "mongodb",
}

API_CANDIDATES = (
    "/api",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/profile",
    "/api/me",
    "/api/users",
    "/api/user",
    "/api/health",
    "/health",
    "/graphql",
    "/openapi.json",
    "/swagger",
    "/api/docs",
)

HTTP_PROBE_PORTS = frozenset({80, 443, 3000, 5000, 8000, 8080, 8081, 8180, 11434})

# Extra ports scanned when initial probe finds multiple services (discovery, not cheat sheet)
EXTENDED_PORTS = {
    23: "telnet",
    25: "smtp",
    139: "netbios",
    445: "smb",
    5900: "vnc",
    6667: "irc",
    8180: "tomcat-alt",
}
