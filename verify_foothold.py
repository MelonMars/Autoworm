import uuid
from tools.registry import REGISTRY

def verify_foothold(host) -> bool:
    if not hasattr(host, 'foothold') or not host.foothold:
        return False

    check_token = f"AGENT_VERIFY_{uuid.uuid4().hex[:8]}"
    foothold = host.foothold
    foothold_type = foothold.get("type")
    details = foothold.get("details", {}) if isinstance(foothold.get("details"), dict) else {}

    print(f"[*] Verifying foothold via {foothold_type}...")

    if foothold_type == "webshell":
        tool = REGISTRY.get("curl_webshell_exec")
        if not tool:
            host.foothold = None
            return False

        from executor import execute_action
        execution_info, _ = execute_action(f"Run '{check_token}'", tool, host)
        if execution_info.get("ok") and check_token in str(execution_info.get("result", "")):
            return True

    elif foothold_type in ["bind_shell", "reverse_shell"]:
        tool = REGISTRY.get("netcat_exec")
        if not tool:
            print("[-] netcat_exec tool not registered.")
            host.foothold = None
            return False
            
        port = details.get("port")
        
        if not port and "CVE-2011-2523" in getattr(host, "vulnerabilities", {}):
            print("[*] No port specified in foothold. Inferring port 6200 from vsftpd CVE.")
            port = 6200
            
        if not port:
            print("[-] No port specified for shell verification.")
            host.foothold = None
            return False

        result = tool.execute_fn({
            "target_ip": host.ip,
            "port": port,
            "command": f"echo {check_token}",
            "timeout": 10
        })
        
        if result.get("code") == 0 and check_token in result.get("stdout", ""):
            print("[+] Foothold VERIFIED. Active access confirmed.")
            return True
        else:
            print(f"[-] Foothold verification failed. Output: {result.get('stdout', '')} {result.get('stderr', '')}")

    elif foothold_type in ["ssh_key", "ssh_key_drop"]:
        tool = REGISTRY.get("ssh_exec")
        if not tool:
            host.foothold = None
            return False
            
        from executor import execute_action
        execution_info, _ = execute_action(f"echo {check_token}", tool, host)
        if execution_info.get("ok") and check_token in str(execution_info.get("result", "")):
            print("[+] Foothold VERIFIED. Active access confirmed.")
            return True
        else:
            print(f"[-] Foothold verification failed.")

    else:
        print(f"[-] Verification for foothold type '{foothold_type}' is not supported.")

    host.foothold = None
    return False
