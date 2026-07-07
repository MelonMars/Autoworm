from llm import request_llm, extract_json
import json
def evaluate_action_progress(host, last_result, remaining_actions, phase):
    prompts = json.load(open("prompts.json"))
    next_step = remaining_actions[0]
    
    prompt = prompts[phase]["Reflector"]["Prompt"].format(last_result, host.facts, host.services, remaining_actions, next_step)
    raw = request_llm(prompt, system=prompts[phase]["Reflector"]["System"], enable_thinking=False, do_sample=False, max_new_tokens=256)
    try:
        return extract_json(raw)
    except Exception:
        return {"decision": "continue", "reason": "Reflector failed to parse"}