from tools.registry import register
from tools.base import Tool, Param

def traceroute_cmd(a: dict) -> list[str]:
    # -n: don't resolve IPs to hostnames (faster)
    # -w 1: wait max 1 second for response
    # -q 1: send 1 probe per hop (faster for agents)
    return ["traceroute", "-n", "-w", "1", "-q", "1", a["target_ip"]]

traceroute = register(Tool(
    name="traceroute",
    description="Maps the network path to the target host. Useful for identifying network boundaries, firewalls (shown as * * *), and internal router IPs.",
    params=[
        Param("target_ip", "string", "IP address of the target."),
    ],
    build_command=traceroute_cmd,
))