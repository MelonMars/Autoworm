from llm import request_llm, extract_json

PROGRESS_SYSTEM = """You are a progress tracker for an agent. Your job is to determine if there are enough hypotheses to start trying them out, or if more information is needed. You will output JSON describing the progress status.

Schema: {
    "progress": str, // one of "ready", "more_info_needed", "uncertain"
    "reasoning": str // a brief explanation of why this progress status was chosen
}
"""

def assess_progress(hypotheses, unknowns, term_result):
    prompt = f"""
Hypotheses: {hypotheses}
Unknowns: {unknowns}
"""
    raw = request_llm(prompt, system=PROGRESS_SYSTEM,
                      enable_thinking=False, do_sample=False, max_new_tokens=256)
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"progress": "uncertain", "reasoning": "Failed to extract JSON from LLM response.", "_raw": raw}

    data.setdefault("progress", "uncertain")
    data.setdefault("reasoning", "")
    return data