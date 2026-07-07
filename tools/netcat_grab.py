from tools.registry import register
from tools.base import Tool, Param

def netcat_cmd(a: dict) -> list[str]:
    # -w 3: timeout after 3 seconds of inactivity
    # -q 1: wait 1 second after EOF before closing
    return ["nc", "-w", "3", "-N", a["target_ip"], str(a["port"])]

# netcat_grab = register(Tool(
#     name="netcat_grab",
#     description="Connects to a TCP port and reads the raw service banner. Use this when nmap fails to identify a service, or to grab raw text banners (FTP, SSH, SMTP, custom services).",
#     params=[
#         Param("target_ip", "string", "IP address of the target."),
#         Param("port", "integer", "TCP port to connect to."),
#     ],
#     build_command=netcat_cmd,
# ))