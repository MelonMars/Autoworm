import os
import shlex
from tools.registry import register
from tools.base import Tool, Param
import base64

def ssh_put_cmd(a: dict) -> list[str]:
    local_path = a["local_path"]
    remote_os = a["remote_os"].lower()
    if os.path.isdir(local_path):
        local_path = a["local_path"]
        remote_os = a["remote_os"].lower()

        ssh_prefix = (
            "ssh -i {key} -o StrictHostKeyChecking=no -o BatchMode=yes "
            "-o ConnectTimeout=10 {user}@{ip}"
        ).format(
            key=shlex.quote(a["key_path"]),
            user=shlex.quote(a["user"]),
            ip=shlex.quote(a["target_ip"]),
        )

        rp = shlex.quote(a["remote_path"])

        if os.path.isdir(local_path):
            abspath = os.path.abspath(local_path)
            parent = os.path.dirname(abspath) or "."
            name = os.path.basename(abspath)
            local = "tar czf - -C {parent} -exclude='__pycache__' --exclude='.git' {name}".format(
                parent=shlex.quote(parent), name=shlex.quote(name))

            rp = a["remote_path"]
            if remote_os == "windows":
                remote = "mkdir {rp} 2>nul & tar xzf - -C {rp}".format(rp=rp)
            else:
                remote = "mkdir -p {rp} && tar xzf - -C {rp}".format(rp=shlex.quote(rp))

            pipeline = "{local} | {ssh} {remote}".format(
                local=local, ssh=ssh_prefix, remote=shlex.quote(remote))
            return ["sh", "-c", pipeline]


        return ["sh", "-c", pipeline]
    else:
        with open(local_path, "rb") as fh:
            encoded = base64.b64encode(fh.read()).decode()
        if remote_os == "windows":
            remote = f"powershell -Command \"[IO.File]::WriteAllBytes('{a['remote_path']}', [Convert]::FromBase64String('{encoded}'))\""
        else:
            remote = f"echo '{encoded}' | base64 -d > {shlex.quote(a['remote_path'])}"
        pipeline = f"{ssh_prefix} {shlex.quote(remote)}"
        return ["sh", "-c", pipeline]

ssh_put = register(Tool(
    name="ssh_put",
    description="Transfer a local file or directory to a remote host over SSH, base64-encoded so no scp/sftp is required. Files need only `base64` on the remote; directories also need `tar`.",
    params=[
        Param("target_ip", "string", "IP address of the target."),
        Param("user", "string", "SSH username."),
        Param("key_path", "string", "Path to the SSH private key file on the local machine."),
        Param("local_path", "string", "Path to the local file or directory to transfer."),
        Param("remote_path", "string", "Destination path on the remote host (a directory for the directory case, a file path for the file case)."),
        Param("remote_os", "string", "Detected OS of the remote host: 'unix' (linux/mac) or 'windows'.", enum=["unix", "windows"]),
    ],
    build_command=ssh_put_cmd,
    category="transfer"
))