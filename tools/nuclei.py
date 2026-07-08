from tools.registry import register
from tools.base import Tool, Param

def nuclei_command(a: dict) -> list[str]:
    profiles = {
        "cves":      ["-tags", "cve"],
        "exposures": ["-tags", "exposure,exposed-panels"],
        "misconfig": ["-tags", "misconfiguration"],
        "tech":      ["-tags", "tech"],
        "takeover":  ["-tags", "takeover"],
        "full":      [],
    }
    cmd = ["nuclei", "-u", a["target"], *profiles[a["scan_type"]]]

    if a.get("severity"):    cmd += ["-severity", a["severity"]]
    if a.get("templates"):   cmd += ["-t", a["templates"]]
    if a.get("exclude_tags"):cmd += ["-etags", a["exclude_tags"]]

    if a.get("rate_limit"):  cmd += ["-rl", str(a["rate_limit"])]
    if a.get("concurrency"): cmd += ["-c", str(a["concurrency"])]
    if a.get("timeout"):     cmd += ["-timeout", str(a["timeout"])]

    if a.get("headers"):
        for h in a["headers"].split(","):
            cmd += ["-H", h.strip()]

    if a.get("follow_redirects"): cmd.append("-fr")
    if a.get("json_output"):      cmd.append("-jsonl")

    cmd += ["-silent", "-nc", "-duc"]
    return cmd

nuclei = register(Tool(
    name="nuclei",
    description="Template-based vulnerability scanner for hosts and web services.",
    params=[
        Param("target", "string", "URL or host to scan, e.g. 'https://example.com'."),
        Param("scan_type", "string", "Template profile.",
            enum=[("cves", "user"), ("exposures", "user"), ("tech", "user")]),
        Param("severity", "string", "Filter by severity, e.g. 'critical,high'.", required=False),
        Param("templates", "string", "Template path/dir or -id to run.", required=False),
        Param("exclude_tags", "string", "Tags to skip, e.g. 'dos,fuzz'.", required=False),
        Param("rate_limit", "integer", "Max requests per second.", required=False),
        Param("concurrency", "integer", "Max concurrent templates.", required=False),
        Param("timeout", "integer", "Per-request timeout in seconds.", required=False),
        Param("headers", "string", "Custom headers, comma-separated 'K: V' pairs.", required=False),
        Param("follow_redirects", "boolean", "Add -fr to follow redirects.", required=False),
        Param("json_output", "boolean", "Emit JSONL results.", required=False),
    ],
    build_command=nuclei_command,
    category=["recon"],
))