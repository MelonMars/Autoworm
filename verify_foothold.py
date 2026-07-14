import uuid
from tools.registry import REGISTRY
from executor import execute_action

MSF_FOOTHOLD_TYPES = frozenset({"meterpreter", "msf_shell"})


def verify_foothold(host) -> bool:
    if not hasattr(host, 'foothold') or not host.foothold:
        return False

    check_token = f"AGENT_VERIFY_{uuid.uuid4().hex[:8]}"

    print(f"[*] Verifying foothold via {host.foothold.get('type')}...")

    foothold_type = host.foothold["type"]

    if foothold_type == "webshell":
        tool = REGISTRY["curl_webshell_exec"]
        execution_info, _ = execute_action(f"Run '{check_token}'", tool, host)

    elif foothold_type == "reverse_shell":
        tool = REGISTRY["shell_session_exec"]
        execution_info, _ = execute_action(f"echo {check_token}", tool, host)

    elif foothold_type == "ssh_key_drop":
        tool = REGISTRY["ssh_exec"]
        execution_info, _ = execute_action(f"echo {check_token}", tool, host)
    else:
        return False

    if execution_info["ok"]:
        result_str = str(execution_info.get("result", ""))
        if check_token in result_str:
            print("[+] Foothold VERIFIED. Active access confirmed.")
            return True
        else:
            print(f"[-] Foothold verification failed. Token not found in output: {result_str}")

    host.foothold = None
    return False
