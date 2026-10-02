"""Ollama tool schemas."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and folders under a directory inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Directory relative to workspace."}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "GET an http or https URL and return status plus body text.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_local",
            "description": "Passive header check of a localhost URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_url",
            "description": "Passive review of one http or https URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "profile_target",
            "description": "Full localhost profile: ports, headers, robots.txt, sitemap.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_target",
            "description": "Merge scans and rank where to focus review.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_api_routes",
            "description": "Discover and probe localhost API routes.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_playbook",
            "description": "Full localhost review pipeline with snapshot save.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_auth_flow",
            "description": "Test login and JWT access on localhost.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_site",
            "description": "Map localhost pages from sitemap and links.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_runs",
            "description": "Diff two saved snapshots.",
            "parameters": {
                "type": "object",
                "properties": {
                    "snapshot_a": {"type": "string"},
                    "snapshot_b": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show_findings",
            "description": "Show structured session findings.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_xss",
            "description": "Auto-scan localhost for reflected XSS. Optional custom payload(s), path, param.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "payload": {"type": "string", "description": "Custom XSS probe string"},
                    "payloads": {"type": "array", "items": {"type": "string"}},
                    "path": {"type": "string"},
                    "param": {"type": "string"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_xss",
            "description": (
                "Test one GET param with a payload you craft. "
                "Use for targeted XSS checks after finding search/forms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "path": {"type": "string", "description": "e.g. /search"},
                    "param": {"type": "string", "description": "e.g. q"},
                    "payload": {"type": "string", "description": "XSS string to inject verbatim"},
                },
                "required": ["target", "path", "param", "payload"],
            },
        },
    },
]
