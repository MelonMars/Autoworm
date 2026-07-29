import os
import requests
import subprocess
from tools.registry import register
from tools.base import Tool, Param

NSE_SCRIPT_DIR = os.path.abspath("nmap_scripts")
os.makedirs(NSE_SCRIPT_DIR, exist_ok=True)

NMAP_GITHUB_RAW_URL = "https://raw.githubusercontent.com/nmap/nmap/master/scripts/{}.nse"

VALID_CATEGORIES = {"vuln", "safe", "exploit", "auth", "discovery",
                    "default", "intrusive", "brute", "dos", "external",
                    "fuzzer", "malware", "version", "broadcast"}

def _is_category(query: str) -> bool:
    return query.lower() in VALID_CATEGORIES

def _download_nse_script(script_name: str) -> tuple[bool, str]:
    filename = f"{script_name}.nse"
    filepath = os.path.join(NSE_SCRIPT_DIR, filename)

    if os.path.exists(filepath):
        return True, "Loaded from local cache."

    url = NMAP_GITHUB_RAW_URL.format(script_name)
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            return True, "Downloaded successfully."
        else:
            return False, f"Script '{script_name}' not found (HTTP {resp.status_code})."
    except Exception as e:
        return False, f"Download failed: {e}"

def _nmap_execute(args: dict) -> dict:
    target = args["target_ip"]
    scan_type = args.get("scan_type", "version")
    ports = args.get("ports", "")
    script_name = args.get("script_name", "")
    script_args = args.get("script_args", "")

    cmd = ["nmap", "-Pn"]

    if scan_type == "quick":
        cmd.extend(["-T4", "-F"])
    elif scan_type == "version":
        cmd.extend(["-sV", "-sC", "-T4"])
    elif scan_type == "os":
        cmd.extend(["-O", "-T4"])
    elif scan_type == "full_tcp":
        cmd.extend(["-p-", "-sV", "-T4"])
    elif scan_type == "script":
        if not script_name:
            return {"code": 1, "stdout": "", "stderr": "scan_type 'script' requires 'script_name'."}
        
        if _is_category(script_name):
            cmd.extend(["--script", script_name])
        else:
            ok, msg = _download_nse_script(script_name)
            if not ok:
                return {"code": 1, "stdout": "", "stderr": msg}
            script_path = os.path.join(NSE_SCRIPT_DIR, f"{script_name}.nse")
            cmd.extend(["--script", script_path])

    if ports:
        cmd = [c for c in cmd if c not in ("-p-", "-F")]
        cmd.extend(["-p", ports])

    if script_args:
        cmd.extend(["--script-args", script_args])

    cmd.append(target)

    try:
        timeout = 600 if scan_type == "version" else 300 if scan_type == "full_tcp" else 240
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": " ".join(cmd),
            "code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"code": 124, "stdout": "", "stderr": f"Nmap scan timed out after {timeout}s."}
    except Exception as e:
        return {"code": 1, "stdout": "", "stderr": str(e)}

nmap_tool = register(Tool(
    name="nmap",
    description=(
        "Executes Nmap for network discovery, port scanning, service version detection, OS detection, and NSE scripts. "
        "Use 'quick' for fast top-100 port checks. "
        "Use 'version' (default) for standard deep recon (service versions + default scripts). "
        "Use 'full_tcp' to scan all 65535 ports. "
        "Use 'script' to run NSE categories (e.g., 'vuln', 'safe') or specific scripts."
    ),
    params=[
        Param("target_ip", "string", "Target IP address."),
        Param("scan_type", "string", "Type of scan to perform.", 
              enum=["quick", "version", "os", "full_tcp", "script"], required=False),
        Param("ports", "string", "Specific ports to scan (e.g., '80,443' or '1-1000'). Overrides default scan ranges.", required=False),
        Param("script_name", "string", "NSE script name or category (only used if scan_type='script').", required=False),
        Param("script_args", "string", "Arguments for the NSE script (e.g., 'smbusername=admin').", required=False),
    ],
    execute_fn=_nmap_execute,
    category=["recon", "foothold"],
    examples=[
        "Light recon top ports: scan_type='quick'",
        "Deep recon service versions: scan_type='version', ports='1-1000'",
        "Full TCP scan: scan_type='full_tcp'",
        "Run vuln scripts on port 445: scan_type='script', script_name='vuln', ports='445'",
        "Run smb-vuln-ms17-010: scan_type='script', script_name='smb-vuln-ms17-010', ports='445'",
    ],
))