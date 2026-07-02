from tools.registry import register
from tools.base import Tool, Param

def nmap_command(a: dict) -> list[str]:
    profiles = {"discovery": ["-sn"], "version": ["-sV"],
                "syn": ["-sS"], "full": ["-sS", "-sV", "-p-"]}
    cmd = ["nmap", *profiles[a["scan_type"]]]
    if a.get("ports"): cmd += ["-p", a["ports"]]
    cmd.append(a["target_ip"])
    return cmd

nmap = register(Tool(
    name="nmap",
    description="Network scanner for host and service discovery.",
    params=[
        Param("target_ip", "string", "IP or CIDR to scan."),
        Param("scan_type", "string", "Scan profile.",
                enum=[("discovery", "user"), ("version", "user"),
                    ("syn", "root"), ("full", "root")]),
        Param("ports", "string", "Port spec, e.g. '22,80,443' or '1-1000'.",
              required=False),
    ],
    build_command=nmap_command,
))