from tools.registry import register
from tools.base import Tool, Param

def smb_info_cmd(a: dict) -> list[str]:
        return ["rpcclient", "-U", "", "-N", "-c", "srvinfo;netshareenumall;lsaenumsid", a["target_ip"]]

# smb_info = register(Tool(
#     name="smb_info",
#     description="Attempts to extract basic info from SMB/RPC null sessions (OS version, shares, SIDs). Only use if port 445 is open and nmap identifies SMB.",
#     params=[
#         Param("target_ip", "string", "IP address of the target."),
#     ],
#     build_command=smb_info_cmd,
# ))