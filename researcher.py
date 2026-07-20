from proc_run import run
from llm import request_llm, extract_json
from validate_args import validate_args
import logging

logger = logging.getLogger(__name__)

SEARCH_SYSTEM = """You are the research phase of an executor agent. Before an action is executed, you may gather information using the available search tools.

Decide ONE step at a time. Output JSON:
{
  "action": "search" | "done",
  "tool": str,        // required when action=="search"; must be a listed search tool
  "arguments": {},    // args matching that tool's schema
  "rationale": str
}

Use "done" once you have enough information. You only have the search tools here; you cannot execute the main action."""

def run_research(action, exec_tool, host, search_tools, search_tool_objects, max_steps=5):
    if isinstance(search_tools, str):
        catalog = search_tools
        tool_list = search_tool_objects or []
    else:
        tool_list = list(search_tools)
        catalog = "\n\n".join(
            f"- {t.name}: {t.description}\n{t.params_doc()}" for t in tool_list
        )

    tool_lookup = {t.name: t for t in tool_list}
    findings = []
    
    for _ in range(max_steps):
        prompt = f"""
Upcoming action (do NOT execute here): {action}
Execution tool to be used later: {exec_tool.name} — {exec_tool.description}

Search tools available now:
{catalog}

Known Facts: {host.facts}
Discovered Services: {host.services}
OS: {host.os}   Hostname: {host.hostname}   Host IP: {host.ip}
"""
        if findings:
            prompt += "\nResearch so far:\n"
            for f in findings:
                prompt += f"- {f['tool']}({f['args']}) -> {f['observation']}\n"

        raw = request_llm(prompt, system=SEARCH_SYSTEM,
                          enable_thinking=True, do_sample=False, max_new_tokens=4096)
        try:
            parsed = extract_json(raw)
        except Exception:
            logger.error("Research LLM failed to parse JSON. Halting research.")
            break

        if parsed.get("action") == "done":
            logger.info("Research phase concluded by LLM.")
            break

        st = tool_lookup.get(parsed.get("tool"))
        if st is None:
            findings.append({"tool": parsed.get("tool"), "args": {}, "observation": "no such search tool"})
            continue

        args = parsed.get("arguments", {})
        err = validate_args(args, st)
        if err:
            findings.append({"tool": st.name, "args": args, "observation": f"bad args: {err}"})
            continue

        result = st.execute_fn(args) if st.execute_fn is not None else run(st.build_command(args))
        
        obs = (result.get("stdout") or result.get("stderr") or f"exit {result.get('code')}")
        logger.info(f"  [Research] Tool '{st.name}' executed.")
        logger.debug(f"  [Research] Args: {args} | Result: {obs.strip()[:500]}")
        
        findings.append({"tool": st.name, "args": args, "observation": obs.strip()[:800]})

    if not findings:
        return ""
    return "Research findings:\n" + "\n".join(
        f"{f['tool']}({f['args']}): {f['observation']}" for f in findings
    )
