from llm import request_llm, extract_json
import json

def evaluate_action_progress(host, last_result, remaining_actions, phase):
    prompts = json.load(open("prompts.json"))
    next_step = remaining_actions[0] if remaining_actions else "No further actions"
    
    prompt_template = prompts[phase]["Reflector"]["Prompt"]
    
    prompt = prompt_template
    prompt = prompt.replace("{last_result}", str(last_result))
    prompt = prompt.replace("{facts}", str(host.facts))
    prompt = prompt.replace("{services}", str(host.services))
    prompt = prompt.replace("{remaining_actions}", str(remaining_actions))
    prompt = prompt.replace("{next_step}", str(next_step))

    raw = request_llm(
        prompt, 
        system=prompts[phase]["Reflector"]["System"], 
        enable_thinking=False, 
        do_sample=False, 
        max_new_tokens=256
    )
    
    try:
        return extract_json(raw)
    except Exception:
        return {"decision": "continue", "reason": "Reflector failed to parse"}