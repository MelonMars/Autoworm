from tools.registry import register
from tools.base import Tool, Param

def dig_cmd(a: dict) -> list[str]:
    cmd = ["dig", "+short", "-noall", "-answer"]
    if a["query_type"] == "PTR":
        cmd.append(f"{a['target']}.in-addr.arpa")
    else:
        cmd.append(a["target"])
    cmd.append(a["query_type"])
    return cmd

dig_lookup = register(Tool(
    name="dig_lookup",
    description="Performs DNS lookups. Crucial for finding domain names associated with an IP (PTR record) or checking for specific records (A, AAAA, CNAME, TXT).",
    params=[
        Param("target", "string", "IP address or Domain name to query."),
        Param("query_type", "string", "Type of DNS record to query.",
              enum=["A", "AAAA", "PTR", "CNAME", "TXT", "ANY"]),
    ],
    build_command=dig_cmd,
))