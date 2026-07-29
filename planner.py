from llm import request_llm, extract_json
import json
import logging
from tools.base import render_tool

logger = logging.getLogger(__name__)

STRATEGIST_SYSTEM = """You are a high-level penetration test strategist. 
Given the target host state and the current phase, generate a brief, high-level step-by-step strategy. 
Do not specify exact tools or arguments. Just list the logical steps to achieve the phase goal.
Output ONLY JSON: {"strategy": ["step 1", "step 2", "step 3"]}
"""
def generate_strategy(host, phase, hypothesis=None):
    prompts = json.load(open("prompts.json"))
    prompt = f"""
Phase: {phase}
Host IP: {host.ip}
OS: {host.os}
Services: {host.services}
Known Vulnerabilities: {host.vulnerabilities}
Current Hypothesis (if any): {hypothesis}
"""
    raw = request_llm(prompt, system=STRATEGIST_SYSTEM, enable_thinking=False, max_new_tokens=2048)
    try:
        data = extract_json(raw)
        return data.get("strategy", [])
    except Exception:
        return []

def plan_next_actions(host, inferences, signals, unknowns, hypothesis, tools, phase, prior_failure, objective=None, strategy_directive=None, plan_mode="sequential", overarching_strategy=None, cve_context=None):
    prompts = json.load(open("prompts.json"))
    print(f"[*] Planning next actions for phase: {phase} (Mode: {plan_mode})")
    
    PLANNER_SYSTEM = prompts[phase]["Planner"]["System"]

    if plan_mode == "single":
        mode_instruction = "IMPORTANT: Generate EXACTLY ONE next action to take based on the current state. Do not generate a list."
    else:
        mode_instruction = "Generate a sequential list of next actions to take."

    PLANNER_SYSTEM += f"\n\nPLAN MODE INSTRUCTION: {mode_instruction}"

    if overarching_strategy:
        PLANNER_SYSTEM += f"\n\nOVERARCHING STRATEGY TO FOLLOW:\n{json.dumps(overarching_strategy)}"

    prompt = prompts[phase]["Planner"]["Prompt"]
    prompt = prompt.replace("{host}", str(host))
    prompt = prompt.replace("{inferences}", str(inferences))
    prompt = prompt.replace("{signals}", str(signals))
    prompt = prompt.replace("{unknowns}", str(unknowns))
    prompt = prompt.replace("{hypothesis}", str(hypothesis))
    tools_str = "\n\n".join(render_tool(t) for t in tools)
    prompt = prompt.replace("{tools}", tools_str)
    prompt = prompt.replace("{prior_failure}", str(prior_failure))
    prompt = prompt.replace("{objective}", str(objective))
    prompt = prompt.replace("{host.ip}", str(host.ip))
    prompt = prompt.replace("{host.os}", str(host.os))
    prompt = prompt.replace("{host.services}", str(host.services))
    prompt = prompt.replace("{host.vulnerabilities}", str(host.vulnerabilities))
    prompt = prompt.replace("{strategy_directive}", str(strategy_directive or ""))
    prompt = prompt.replace("{cve_context}", str(cve_context or "No context provided."))
    prompt = prompt.replace("{host.facts}", str(host.facts))
    prompt = prompt.replace("{host.hostname}", str(host.hostname or "Unknown"))

    raw = request_llm(
            prompt,
            system=PLANNER_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=2048
        )
        
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"Next Actions": [], "_raw": raw}

    if plan_mode == "single" and len(data.get("Next Actions", [])) > 1:
        data["Next Actions"] = [data["Next Actions"][0]]

    print(f"[*] Planned {len(data.get('Next Actions', []))} next actions for phase '{phase}'.")
    data.setdefault("Next Actions", [])
    return data