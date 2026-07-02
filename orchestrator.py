from analysis import analyze
from planner import plan_next_actions
from executor import execute_action
from tool_normalizer import normalize_tool_output
from hypothesizer import generate_hypotheses
from progress import assess_progress
from memory import Campaign, Host
from reflector import evaluate_action_progress
import tools
from tools.registry import REGISTRY
import networkx as nx

test_host = Host(
    id="host1",
    services={},
    facts={},
    state="unknown",
    os=None,
    hostname=None,
    hypotheses=[],
    ip = "127.1.2.3"
)

# Define memory
campaign = Campaign(graph=nx.DiGraph(), hosts=[test_host])

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

# Get basic facts of the host
for host in campaign.hosts:
    progress = {"progress": "more_info_needed"}
    while progress["progress"] != "ready":
        analysis_result = analyze(host, campaign.graph)
        host.facts.update(analysis_result["facts"])

        plan = plan_next_actions(host, analysis_result["inferences"],
                                analysis_result["signals"], None, None,
                                list(REGISTRY), phase)
        print("Got plan:", plan)

        actions_queue = list(plan.get("Next Actions", []))
        normalized_result = None

        while actions_queue:
            step = actions_queue.pop(0)
            tool = REGISTRY[step["tool"]]

            execution_info, raw = execute_action(step["action"], tool, host)
            
            if execution_info["ok"]:
                normalized_result = normalize_tool_output(tool, execution_info["result"], host)
                apply_update(host, normalized_result)
            else:
                normalized_result = {"error": execution_info.get("error", "unknown failure")}

            reflection = evaluate_action_progress(host, normalized_result, actions_queue)
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
        hypotheses = [h for h in host.hypotheses if h.confidence > 0.7 and not h.failed_attempts]
        for hypothesis in hypotheses:
            plan = plan_next_actions(host, analysis_result["inferences"], analysis_result["signals"],
                                    analysis_result["unknowns"], hypothesis, list(REGISTRY), phase)
            print("Got plan:", plan)
            step = plan["Next Actions"][0]
            tool = REGISTRY[step["tool"]]

            execution_info, raw = execute_action(step["action"], tool, host)
            if not execution_info["ok"]:
                print("Execution failed:", execution_info["error"])
                hypothesis.failed_attempts.append(execution_info["error"])
                continue
            normalized_result = normalize_tool_output(tool, execution_info["result"], host)
            progress = assess_progress(host.hypotheses, analysis_result["unknowns"], normalized_result, phase)
