from llm import request_llm, extract_json
import json

def plan_next_actions(host, inferences, signals, unknowns, hypothesis, tools, phase, prior_failure, objective=None):
    prompts = json.load(open("prompts.json"))
    PLANNER_SYSTEM = prompts[phase]["Planner"]["System"]

    prompt = prompts[phase]["Planner"]["Prompt"]
    prompt = prompt.replace("{host}", str(host))
    prompt = prompt.replace("{inferences}", str(inferences))
    prompt = prompt.replace("{signals}", str(signals))
    prompt = prompt.replace("{unknowns}", str(unknowns))
    prompt = prompt.replace("{hypothesis}", str(hypothesis))
    prompt = prompt.replace("{tools}", str(tools))
    prompt = prompt.replace("{prior_failure}", str(prior_failure))
    prompt = prompt.replace("{objective}", str(objective))

    raw = request_llm(
            prompt,
            system=PLANNER_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=2048
        )
    print("Planner return raw: ", raw)
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"Next Actions": [], "_raw": raw}

    data.setdefault("Next Actions", [])
    return data