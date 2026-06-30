from llm import request_llm, extract_json

PLANNER_SYSTEM = """You are a planner for an authorized penetration test on a target system. Your job is to generate a list of next actions to take, given the current state of the target system, its known facts, signals, inferences, a hypothesis about potential vulnerabilities, and a list of tools available to you. You should reason across the known facts, signals, inferences, and hypothesis to generate a list of next actions that will help you validate or refute the hypothesis and ultimately gain access to the target host.

Schema: {
    "Next Actions": [
        {
            "tool": str, // the name of the tool to use for this action
            "action": str, // a concise description of the action to take
            "priority": float, // a float 0-1: how important this action is relative to others
        },
        ...
    ]
}
"""

def plan_next_actions(host, inferences, signals, hypothesis, tools):
    prompt = f"""
Known Facts: {host.facts}
Discovered Services: {host.services}
OS: {host.os}
Hostname: {host.hostname}
Inferences: {inferences}
Signals: {signals}
Hypothesis: {hypothesis.description}
Hypothesis Evidence: {hypothesis.evidence}
Available Tools: {tools}
"""
    raw = request_llm(
            prompt,
            system=PLANNER_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=512
        )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"Next Actions": [], "_raw": raw}

    data.setdefault("Next Actions", [])
    return data