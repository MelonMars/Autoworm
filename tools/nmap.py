from tools.registry import register
from tools.base import Tool, Param

def nmap_command(a: dict) -> list[str]:
    profiles = {
        "discovery": ["-sn"],
        "version":   ["-sV"],
        "syn":       ["-sS"],
        "udp":       ["-sU"],
        "os":        ["-sS", "-O"],
        "full":      ["-sS", "-sV", "-p-"],
        "aggressive":["-A"],
    }
    cmd = ["nmap", *profiles[a["scan_type"]]]

    if a.get("ports"):
        cmd += ["-p", a["ports"]]
    elif a.get("top_ports"):
        cmd += ["--top-ports", str(a["top_ports"])]

    if a.get("skip_ping"):   cmd.append("-Pn")
    # if a.get("scripts"):     cmd += ["--script", a["scripts"]] # Too slow
    if a.get("timing"):      cmd.append(f"-T{a['timing']}")

    cmd.append(a["target_ip"])
    return cmd

nmap = register(Tool(
    name="nmap",
    description="Network scanner for host and service discovery.",
    params=[
        Param("target_ip", "string", "IP or CIDR to scan."),
        Param("scan_type", "string", "Scan profile.",
            enum=[("discovery", "user"), ("version", "user")]),
        Param("ports", "string", "Port spec, e.g. '22,80,443' or '1-1000'.", required=False),
        Param("top_ports", "integer", "Scan N most common ports (ignored if 'ports' set).", required=False),
        Param("skip_ping", "boolean", "Add -Pn to skip host discovery.", required=False),
        # Param("scripts", "string", "NSE script(s), e.g. 'default,vuln' or 'http-title'.", required=False),
        Param("timing", "integer", "Timing template 0-5.", required=False),
    ],
    build_command=nmap_command,
))