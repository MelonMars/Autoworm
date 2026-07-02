from llm import request_llm, extract_json

REFLECTOR_SYSTEM = """You are an agent reflector. You review the result of an action that was just executed and decide what to do next.
You have a queue of remaining planned actions. Based on the new state of the host, decide:

1. "continue": The next action in the queue is still perfectly valid.
2. "modify_and_continue": The next action needs slight tweaks based on new facts. Provide the modified action.
3. "replan": The result changes things fundamentally. Stop executing and go back to the planner.
4. "hypothesize": We have gathered enough information, skip the rest of the queue and generate hypotheses.

Output strictly JSON: {"decision": "continue|modify_and_continue|replan|hypothesize", "reason": "...", "modified_next_action": { ... optional ... }}
"""

def evaluate_action_progress(host, last_result, remaining_actions):
    if not remaining_actions:
        return {"decision": "hypothesize", "reason": "Queue empty"}
        
    next_step = remaining_actions[0]
    
    prompt = f"""
Last Action Result: {last_result}
Current Facts: {host.facts}
Current Services: {host.services}

Remaining Planned Actions:
{remaining_actions}

Next action to evaluate: {next_step}

Evaluate if the next action is still the best use of time given the latest result. If the action should be changed based on previous results, provide the modified action in the "modified_next_action" field. If the next action is still valid, return "continue". If the next action is no longer valid, return "replan". If we have enough information to generate hypotheses, return "hypothesize"."""
    
    raw = request_llm(prompt, system=REFLECTOR_SYSTEM, enable_thinking=False, do_sample=False, max_new_tokens=256)
    try:
        return extract_json(raw)
    except Exception:
        return {"decision": "continue", "reason": "Reflector failed to parse"}