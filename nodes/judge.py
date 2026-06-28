import importlib
import inspect
import pkgutil

from nodes.node import Node
from tools.tool import Tool
from llm import request_llm


class Judge(Node):
    name = "Judge"
    description = "Evaluates Plan's directive against the hypothesis and prior failures; approves, revises, or rejects."
    MAX_STEPS = 3
    RESULT_CAP = 2000

    @staticmethod
    def get_research_tools() -> list[type[Tool]]:
        tools = []
        for _, module_name, _ in pkgutil.iter_modules(["tools"]):
            module = importlib.import_module(f"tools.{module_name}")
            for _, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and issubclass(obj, Tool)
                        and obj is not Tool and getattr(obj, "kind", None) == "research"):
                    tools.append(obj)
        return tools

    def run(self, state):
        plan = state.memory.get("plan")
        if not plan:
            return {"verdict": "reject", "reason": "no plan to judge"}

        tools = self.get_research_tools()
        tools_by_name = {t.name: t for t in tools}
        scratch = []

        for _ in range(self.MAX_STEPS):
            decision = self.parse(request_llm(self.build_prompt(state, plan, tools, scratch)))

            if decision.get("action") == "tool":
                tool_cls = tools_by_name.get(decision.get("tool"))
                if not tool_cls:
                    scratch.append(f"[error] no such tool '{decision.get('tool')}'")
                    continue
                result = tool_cls().run(**decision.get("args", {}))
                scratch.append(f"[tool] {decision['tool']}({decision.get('args', {})})\n"
                               f"[result] {result[:self.RESULT_CAP]}")
                continue

            if decision.get("action") == "verdict":
                return self._finalize(state, plan, decision)

            scratch.append("[error] malformed decision, retry")

        forced = self.parse(request_llm(self.build_prompt(state, plan, tools, scratch, force=True)))
        return self._finalize(state, plan, forced)

    def _finalize(self, state, plan, decision):
        verdict = decision.get("verdict", "approve")
        reason = decision.get("reason", "")

        if verdict == "revise":
            new_plan = decision.get("plan", plan)
            state.memory["plan"] = new_plan
            plan = new_plan

        state.history.append({"node": self.name, "verdict": verdict,
                              "reason": reason, "plan": plan})
        return {"verdict": verdict, "reason": reason, "plan": plan}

    def build_prompt(self, state, plan, tools, scratch, force=False) -> str:
        h = state.hypothesis
        catalog = "\n".join(
            f"- {t.name}({t.parameters}): {t.description}" for t in tools
        )
        failures = "\n".join(f"- {f}" for f in h.failures) or "none yet"
        trail = "\n\n".join(scratch) or "none"

        instruction = (
            'Output your verdict JSON now: '
            '{"action":"verdict","verdict":"approve|revise|reject","reason":"...","plan":"<if revise>"}'
            if force else
            "Judge the plan. If it's sound, approve. If it's close but flawed (wrong target, "
            "repeats a known failure, missing a step), revise it yourself. If it's fundamentally "
            "wrong for this hypothesis, reject so planning restarts. Optionally use a research "
            "tool first to verify.\n"
            'Respond ONLY with JSON, one of:\n'
            '  {"action":"tool","tool":"<name>","args":{...}}\n'
            '  {"action":"verdict","verdict":"approve","reason":"..."}\n'
            '  {"action":"verdict","verdict":"revise","reason":"...","plan":"<corrected directive>"}\n'
            '  {"action":"verdict","verdict":"reject","reason":"..."}'
        )

        return (
            f"You review a plan before it executes. Be strict but decisive.\n\n"
            f"HYPOTHESIS\n{h.description}\n\n"
            f"OBSERVATIONS\n{h.observations}\n\n"
            f"SUMMARIES\n{h.summaries}\n\n"
            f"ALREADY FAILED\n{failures}\n\n"
            f"PLAN UNDER REVIEW\n{plan}\n\n"
            f"RESEARCH TOOLS (read-only)\n{catalog}\n\n"
            f"YOUR CHECKS SO FAR\n{trail}\n\n"
            f"{instruction}"
        )

    def parse(self, raw: str) -> dict:
        import json, re
        raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}