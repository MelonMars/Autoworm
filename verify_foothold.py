import socket, subprocess, time, uuid
from tools.registry import REGISTRY

REVERSE_SHELL_WAIT = 8

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]

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
        info, _ = execute_action(f"echo {check_token}", tool, host)
        if info.get("ok") and check_token in str(info.get("result", "")):
            return _ok()
        return _fail(host)

    if ftype == "bind_shell":
        port = details.get("port") or details.get("bind_port")
        if not port:
            print("[-] bind_shell claim missing 'port'.")
            return _fail(host)
        nc = REGISTRY.get("netcat_exec")
        if not nc:
            return _fail(host)
        for attempt in range(3):
            r = nc.execute_fn({
                "target_ip": host.ip,
                "port": int(port),
                "command": f"echo {check_token}",
                "timeout": 5,
            })
            if r.get("code") == 0 and check_token in r.get("stdout", ""):
                return _ok()
            time.sleep(1)
        print(f"[-] bind_shell on {host.ip}:{port} did not echo token.")
        return _fail(host)

    if ftype == "reverse_shell":
        callback_port = details.get("callback_port") or details.get("port")
        print(f"[-] reverse_shell verification requires a live listener on "
              f"port {callback_port}. Re-run the exploit with a listener.")
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

    if ftype == "webshell":
        tool = REGISTRY.get("curl_webshell_exec")
        if not tool:
            return _fail(host)
        from executor import execute_action
        info, _ = execute_action(f"Run '{check_token}'", tool, host)
        if info.get("ok") and check_token in str(info.get("result", "")):
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
