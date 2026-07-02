from llm import request_llm, extract_json
import json

def plan_next_actions(host, inferences, signals, unknowns, hypothesis, tools, phase):
    print("Received tools:", tools)
    prompts = json.load(open("prompts.json"))
    PLANNER_SYSTEM = prompts[phase]["Planner"]["System"]
    prompt = prompts[phase]["Planner"]["Prompt"].format(host=host, inferences=inferences, signals=signals, unknowns=unknowns, hypothesis=hypothesis, tools=tools)
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