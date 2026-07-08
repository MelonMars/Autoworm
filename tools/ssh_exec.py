from tools.registry import register
from tools.base import Tool, Param

def ssh_exec_cmd(a: dict) -> list[str]:
    cmd = [
        "ssh",
        "-i", a["key_path"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{a['user']}@{a['target_ip']}",
        a["command"],
    ]
    return cmd

ssh_exec = register(Tool(
    name="ssh_exec",
    description="Execute a command on a remote host via SSH key authentication. Use when an SSH key has been dropped on the target.",
    params=[
        Param("target_ip", "string", "IP address of the target."),
        Param("user", "string", "SSH username."),
        Param("key_path", "string", "Path to the SSH private key file on the local attacker machine."),
        Param("command", "string", "Command to execute on the remote host."),
    ],
    build_command=ssh_exec_cmd,
    category=["foothold"],
))
