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
    """Check if the query is a valid NSE category (not a specific script)."""
    return query.lower() in VALID_CATEGORIES


def _download_nse_script(script_name: str) -> tuple[bool, str]:
    filename = f"{script_name}.nse"
    filepath = os.path.join(NSE_SCRIPT_DIR, filename)

    if os.path.exists(filepath):
        return True, "Loaded from local cache."

    url = NMAP_GITHUB_RAW_URL.format(script_name)
    try:
        print(f"[*] NSE '{script_name}' not in cache. Downloading from GitHub...")
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            return True, "Downloaded successfully."
        else:
            return False, f"Script '{script_name}' not found (HTTP {resp.status_code}). Use nmap_script_search to find valid scripts."
    except Exception as e:
        return False, f"Download failed: {e}"


def _nmap_exploit_execute(args: dict) -> dict:
    target = args["target_ip"]
    script_query = args["script_name"]       # can be category OR script name
    script_args = args.get("script_args", "")
    ports = args.get("ports", "1-1000")

    if _is_category(script_query):
        cmd = ["nmap", "--script", script_query, "-p", ports]
    else:
        ok, msg = _download_nse_script(script_query)
        if not ok:
            return {"code": 1, "stdout": "", "stderr": msg}

        script_path = os.path.join(NSE_SCRIPT_DIR, f"{script_query}.nse")
        cmd = ["nmap", "--script", script_path, "-p", ports]

    if script_args:
        cmd.extend(["--script-args", script_args])

    cmd.append(target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "cmd": " ".join(cmd),
            "code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"code": 1, "stdout": "", "stderr": str(e)}


nmap_exploit = register(Tool(
    name="nmap",
    description=(
        "Executes an Nmap NSE script or script category against a target. "
        "SCRIPT CATEGORIES (most reliable): 'vuln', 'safe', 'exploit', 'auth', 'discovery', "
        "'default', 'intrusive'. A category runs ALL matching scripts — no need to guess names. "
        "SPECIFIC SCRIPTS: use nmap_script_search FIRST to verify the script exists, "
        "then provide the exact name. Scripts are auto-downloaded from the official Nmap repo."
    ),
    params=[
        Param("target_ip", "string", "Target IP"),
        Param("script_name", "string",
              "Either an NSE CATEGORY ('vuln', 'safe', 'exploit', 'auth', 'discovery', "
              "'intrusive') or an exact NSE script name (e.g. 'smb-vuln-ms17-010'). "
              "CATEGORIES are strongly preferred — they are always valid and run all matching "
              "scripts. If you need a specific script, verify it exists with nmap_script_search "
              "first."),
        Param("script_args", "string", "Arguments for the script", required=False),
        Param("ports", "string", "Ports to scan (default '1-1000')", required=False),
    ],
    execute_fn=_nmap_exploit_execute,
    category=["foothold", "recon"],
    examples=[
        "Run all vuln scripts against 192.168.1.5 on port 445: script_name='vuln', ports='445'",
        "Run all safe discovery scripts on SSH: script_name='safe', ports='22'",
        "Run smb-vuln-ms17-010 specifically: script_name='smb-vuln-ms17-010', ports='445'",
    ],
))