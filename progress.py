from llm import request_llm, extract_json
from json import load

def assess_progress(hypotheses, unknowns, term_result, phase):
    prompts = load(open("prompts.json"))
    PROGRESS_SYSTEM = prompts[phase]["Progress"]["System"]
    prompt = prompts[phase]["Progress"]["Prompt"].format(hypotheses=hypotheses, unknowns=unknowns, term_result=term_result)
    raw = request_llm(prompt, system=PROGRESS_SYSTEM,
                      enable_thinking=False, do_sample=False, max_new_tokens=256)
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"progress": "uncertain", "reasoning": "Failed to extract JSON from LLM response.", "_raw": raw}

    data.setdefault("progress", "uncertain")
    data.setdefault("reasoning", "")
    return data