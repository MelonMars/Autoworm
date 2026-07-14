import json
import os
import requests
from tools.registry import register
from tools.base import Tool, Param

try:
    import paramiko
except ImportError:
    paramiko = None

_FALLBACK_CREDS = [
    {"service": "ssh", "users": ["root", "admin"], "passwords": ["root", "toor", "admin", "password"]},
    {"service": "http", "users": ["admin"], "passwords": ["admin", "password", "1234"]}
]

def _load_creds(service_type):
    path = "wordlists/default_creds.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            return next((item for item in data if item["service"] == service_type), None)
    return next((item for item in _FALLBACK_CREDS if item["service"] == service_type), None)

def _try_ssh(ip, port, user, passwd):
    if not paramiko:
        return False, "Paramiko not installed"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=user, password=passwd, timeout=5, look_for_keys=False, allow_agent=False)
        client.close()
        return True, "Success"
    except paramiko.AuthenticationException:
        return False, "Auth Failed"
    except Exception as e:
        return False, str(e)

def _try_http(login_url, user, passwd, fail_string):
    try:
        data = {"username": user, "user": user, "login": user, "password": passwd, "pass": passwd, "pwd": passwd}
        r = requests.post(login_url, data=data, timeout=5, allow_redirects=True)
        
        if fail_string:
            if fail_string.lower() in r.text.lower():
                return False, "Fail string found"
            return True, "Fail string not found, likely valid"
        
        if r.history and r.history[0].status_code == 302:
            return True, "302 Redirect (Potential Success)"
        if "invalid" not in r.text.lower() and "error" not in r.text.lower() and "denied" not in r.text.lower():
            return True, "No failure indicators in response"
            
        return False, "Failed heuristically"
    except Exception as e:
        return False, str(e)

def execute_default_creds(args: dict) -> dict:
    target_ip = args["target_ip"]
    port = args.get("port", 0)
    service_type = args["service_type"].lower()
    login_url = args.get("login_url", "")
    fail_string = args.get("fail_string", "")
    
    users = args.get("username").split(",") if args.get("username") else []
    passwords = args.get("password").split(",") if args.get("password") else []

    if not users or not passwords:
        cred_set = _load_creds(service_type)
        if not cred_set:
            return {"code": 1, "stdout": "", "stderr": f"No default creds loaded for {service_type}"}
        users = users or cred_set.get("users", [])
        passwords = passwords or cred_set.get("passwords", [])

    findings = []
    for user in users:
        for passwd in passwords:
            if service_type == "ssh":
                p = port or 22
                success, msg = _try_ssh(target_ip, p, user.strip(), passwd.strip())
            elif service_type in ["http", "https", "http_post"]:
                if not login_url:
                    return {"code": 1, "stdout": "", "stderr": "login_url required for http service_type"}
                success, msg = _try_http(login_url, user.strip(), passwd.strip(), fail_string)
            else:
                return {"code": 1, "stdout": "", "stderr": f"Unsupported service_type: {service_type}"}

            status = "[+ SUCCESS]" if success else "[- FAILED ]"
            findings.append(f"{status} {user}:{passwd} on {service_type} - {msg}")

            if success:
                # Stop on first success to save time and context window
                return {"code": 0, "stdout": "\n".join(findings), "stderr": ""}

    return {"code": 0, "stdout": "\n".join(findings), "stderr": "No valid default credentials found."}

default_creds_check = register(Tool(
    name="default_creds_check",
    description="Tests default or provided credentials against SSH or HTTP forms. Stops on first successful login.",
    params=[
        Param("target_ip", "string", "Target IP address."),
        Param("service_type", "string", "Protocol to test.", enum=[("ssh", "user"), ("http", "user")]),
        Param("port", "integer", "Target port (defaults to 22 for SSH, ignored for HTTP).", required=False),
        Param("login_url", "string", "Required for HTTP: The URL of the login form action.", required=False),
        Param("fail_string", "string", "Optional for HTTP: String present in response on failed login.", required=False),
        Param("username", "string", "Single user or comma-separated list. If blank, uses defaults.", required=False),
        Param("password", "string", "Single pass or comma-separated list. If blank, uses defaults.", required=False),
    ],
    execute_fn=execute_default_creds,
    category=["exploit", "foothold"],
))