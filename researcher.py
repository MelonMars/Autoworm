from llm import request_llm, extract_json
from validate_args import validate_args

SEARCH_SYSTEM = """You are the research phase of an executor agent. Before an action is executed, you may gather information using the available search tools.

Decide ONE step at a time. Output JSON:
{
  "action": "search" | "done",
  "tool": str,        // required when action=="search"; must be a listed search tool
  "arguments": {},    // args matching that tool's schema
  "rationale": str
}

Use "done" once you have enough information. You only have the search tools here; you cannot execute the main action."""

def run_research(action, exec_tool, host, search_tools, max_steps=5):
    catalog = "\n".join(
        f"- {t.name}: {t.description}\n{t.params_doc()}" for t in search_tools.values()
    )
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
                          enable_thinking=False, do_sample=False, max_new_tokens=512)
        try:
            parsed = extract_json(raw)
        except Exception:
            break

        if parsed.get("action") == "done":
            break

        st = search_tools.get(parsed.get("tool"))
        if st is None:
            findings.append({"tool": parsed.get("tool"), "args": {},
                             "observation": "no such search tool"})
            continue

        args = parsed.get("arguments", {})
        err = validate_args(args, st)
        if err:
            findings.append({"tool": st.name, "args": args, "observation": f"bad args: {err}"})
            continue

        result = st.execute_fn(args) if st.execute_fn is not None else run(st.build_command(args))
        obs = (result.get("stdout") or result.get("stderr") or f"exit {result.get('code')}")
        findings.append({"tool": st.name, "args": args, "observation": obs.strip()[:800]})

    if not findings:
        return ""
    return "Research findings:\n" + "\n".join(
        f"{f['tool']}({f['args']}): {f['observation']}" for f in findings
    )