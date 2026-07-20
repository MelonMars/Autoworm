from llm import request_llm, extract_json
import json
import logging
from tools.base import render_tool

logger = logging.getLogger(__name__)

def plan_next_actions(host, inferences, signals, unknowns, hypothesis, tools, phase, prior_failure, objective=None, strategy_directive=None):
    prompts = json.load(open("prompts.json"))
    PLANNER_SYSTEM = prompts[phase]["Planner"]["System"]

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

    logger.info(f"Requesting plan from LLM for phase: {phase}")
    logger.debug(f"Planner Prompt:\n{prompt}")
    
    raw = request_llm(
            prompt,
            system=PLANNER_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=2048
        )
        
    logger.debug(f"LLM raw output:\n{raw}")
    
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        logger.error("Failed to extract JSON from planner output.")
        return {"Next Actions": [], "_raw": raw}

    data.setdefault("Next Actions", [])
    logger.info(f"Planner generated {len(data['Next Actions'])} actions.")
    return data