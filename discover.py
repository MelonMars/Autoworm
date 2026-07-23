from analysis import analyze
from deterministic_cve_scan import lookup_cves_for_service
from executor import execute_action
from hypothesizer import generate_hypotheses
from memory import Campaign, Host, build_working_memory
from planner import plan_next_actions
from progress import assess_progress
from reflector import evaluate_action_progress
from tool_normalizer import check_opportunity, normalize_tool_output_search
from tools.base import filter_tools, render_tools, filter_tools
from tools.registry import REGISTRY
from utils import apply_update, merge, sanity_check_args
from service_validator import validate_services

def deterministic_cve_scan(host):
    print("\n[*] === Deterministic CVE Scan (NVD) ===")
    all_cves = []

    for port, svc in host.services.items():
        if not isinstance(svc, dict):
            continue
        product = svc.get("product") or svc.get("name")
        version = svc.get("version")
        if not product or not version:
            print(f"  [{port}] {product or '?'} — no version, skipping")
            continue

        print(f"  [{port}] {product} {version} — querying NVD…")
        cves = lookup_cves_for_service(svc)
        for c in cves:
            tag = " [EXPLOIT]" if c["exploit_available"] else ""
            print(
                f"    → {c['id']}  "
                f"CVSS={c['cvss'].get('score', '?')} "
                f"({c['cvss'].get('severity', '?')}){tag}"
            )
        all_cves.extend(cves)

    if all_cves:
        merge(
            host.vulnerabilities,
            {"cve_scan": {"source": "nvd", "count": len(all_cves), "cves": all_cves}},
        )
        print(f"[+] Deterministic scan found {len(all_cves)} CVE(s).\n")
    else:
        print("[*] No CVEs found.\n")
    return all_cves


def run_discovery_subphase(host, campaign, sub_phase_name, tool_filter, max_actions):
    actions_queue = []
    actions_taken = 0
    working_mem = build_working_memory(host)
    
    initial_plan = plan_next_actions(
        host, [], [], [],
        hypothesis=None, 
        tools=tool_filter, 
        phase=sub_phase_name,
        prior_failure=None
    )

    print(f"[*] Initial plan for {sub_phase_name}: {initial_plan.get('Next Actions', [])}")

    actions_queue = list(initial_plan.get("Next Actions", []))

    while actions_queue and actions_taken < max_actions:
        step = actions_queue.pop(0)
        tool = REGISTRY.get(step["tool"], category="recon")
        
        if not tool:
            continue

        print(f"\n[*] [{sub_phase_name.upper()}] Action {actions_taken + 1}/{max_actions}: {step['action']}")

        sanity_err = sanity_check_args(step.get("arguments", {}), tool, host)
        if sanity_err:
            print(f"[-] {sanity_err}")
            actions_queue.insert(0, {**step, "_inject_error": sanity_err})
            continue

        execution_info, raw = execute_action(step["action"], tool, host, search_tools=filter_tools(REGISTRY, "search"))
        print("Received execution info:", execution_info)
        actions_taken += 1

        if execution_info["ok"]:
            normalized_result = normalize_tool_output_search(tool, execution_info["result"]["stdout"], host)
            apply_update(host, normalized_result, campaign)
            working_mem = build_working_memory(host)
        else:
            normalized_result = {"error": execution_info.get("error", "unknown failure"), "ok": False}

        opportunity = check_opportunity(normalized_result, host)
        if opportunity:
            print("[!!!] OPPORTUNITY DETECTED: Short-circuiting!")
            if opportunity["type"] == "claim":
                host.foothold = opportunity["data"]
            return "opportunistic_foothold"

        if step.get("_inject_error"):
            reflection = {"decision": "replan", "reason": f"Sanity check failed: {step['_inject_error']}"}
        else:
            reflection = evaluate_action_progress(host, normalized_result, actions_queue, sub_phase_name)

        decision = reflection.get("decision", "continue")

        if decision == "replan":
            new_plan = plan_next_actions(host, [], [], [], None, tool_filter, sub_phase_name, prior_failure=reflection)
            new_actions = list(new_plan.get("Next Actions", []))
            actions_queue = new_actions + actions_queue 
        elif decision == "modify_and_continue" and actions_queue:
            actions_queue[0] = reflection["modified_next_action"]
        elif decision == "retry_previous" and execution_info["ok"]:
            actions_queue.insert(0, reflection.get("modified_previous_action", step))
        elif decision == "hypothesize":
            break

    return "continue"


def run_discovery_phase(host: Host, campaign: Campaign):
    print("[*] ========================================")
    print("[*] STARTING DISCOVERY PHASE")
    print("[*] ========================================")

    light_tools = filter_tools(REGISTRY, "recon")
    print("Tools available for light recon:", light_tools)
    status = run_discovery_subphase(host, campaign, "enum_host_light", light_tools, max_actions=5)
    
    if status == "opportunistic_foothold":
        return status

    print("\n[*] Light Recon complete. Analyzing surface area...")
    light_analysis = analyze(host, campaign.graph)
    host.facts.update(light_analysis["facts"]) 


    print("\n[*] Transitioning to Deep Recon...")
    deep_tools = filter_tools(REGISTRY, "recon") 
    status = run_discovery_subphase(host, campaign, "enum_host_deep", deep_tools, max_actions=20)
    
    if status == "opportunistic_foothold":
        return status

    print("\n[*] Deep Recon complete. Generating Hypotheses...")
    validate_services(host)
    deterministic_cve_scan(host)

    final_analysis = analyze(host, campaign.graph)
    new_hypotheses = generate_hypotheses(host, final_analysis["inferences"], final_analysis["signals"])
    host.hypotheses.extend(new_hypotheses.get("Hypotheses", []))
    
    progress = assess_progress(host.hypotheses, final_analysis["unknowns"], None, "enum_host")
    
    if progress["progress"] == "ready":
        return "ready"
        
    return "exhausted"

