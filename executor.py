from llm import request_llm, extract_json
import subprocess
from tools.base import current_privilege
from researcher import run_research
from validate_args import validate_args

def run(argv: list[str], timeout: int = 300) -> dict:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"cmd": argv, "code": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"cmd": argv, "error": "timeout"}

EXECUTOR_SYSTEM = """You are an executor for an agent. Your job is to execute a given action using a specified tool on a target host. Make sure you don't execute any commands that require higher privileges than you currently have.

You need to properly format the tool execution command, based on the information given. You will output JSON describing the tool call:

Schema: {
    "tool": str,        // must equal the given tool name
    "arguments": {},    // object matching the tool's parameter schema
    "rationale": str    // one sentence on why these arguments
}
"""

def execute_action(action, tool, host, search_tools=None, max_retries=2, max_search_steps=5):
    search_tools = {t.name: t for t in (search_tools or [])}
    findings = run_research(action, host, search_tools=search_tools, max_steps=max_search_steps) if search_tools else ""

    attempts = []
    for attempt in range(max_retries + 1):
        prompt = f"""
Objective: {action}
Tool: {tool.name} — {tool.description}
Parameters:
{tool.params_doc()}

Current privilege level: {current_privilege()}

Known Facts: {host.facts}
Discovered Services: {host.services}
OS: {host.os}
Hostname: {host.hostname}
Host IP: {host.ip}
"""

        if findings:
            prompt += f"\nRelevant findings from research:\n{findings}\n"
            
        print("Executing with prompt:", prompt)
        if attempts:
            prompt += "\nPrevious attempts (from you) failed. Fix the arguments (or remove optional arguments):\n"
            for a in attempts:
                prompt += f"- args {a['args']} -> {a['error']}\n"

        max_new_tokens = 512

        raw = request_llm(prompt, system=EXECUTOR_SYSTEM,
                          enable_thinking=False, do_sample=False, max_new_tokens=max_new_tokens)
        print("Tool execution returned:", raw)
        try:
            parsed = extract_json(raw)
        except Exception:
            attempts.append({"args": None, "error": "unparseable LLM output"})
            continue

        args = parsed.get("arguments", {})
        err = validate_args(args, tool)
        if err:
            attempts.append({"args": args, "error": err})
            continue

        need = tool.required_privilege(args)
        if need == "root" and current_privilege() != "root":
            return {"ok": False, "error": "insufficient_privilege",
                    "need": need, "have": current_privilege(), "args": args}, raw

        if tool.execute_fn is not None:
            result = tool.execute_fn(args)
        else:
            result = run(tool.build_command(args))

        if result.get("code") == 0:
            return {"ok": True, "args": args, "rationale": parsed.get("rationale"),
                    "result": result, "attempts": attempt + 1}, raw

        attempts.append({"args": args, "error": result.get("stderr", "").strip()
                         or f"exit {result.get('code')}"})

    return {"ok": False, "error": "max_retries_exhausted",
            "attempts": attempts}, raw