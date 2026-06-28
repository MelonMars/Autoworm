from nodes.node import Node
from tools.tool import Tool
import importlib
import inspect
import pkgutil
from pathlib import Path
from llm import request_llm
from phases import phase_dict
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"

class Action(Node):
    name = "Action"
    description = "Selects and executes one tool from the phase tools"

    @staticmethod
    def get_tools(phase: str) -> list[type[Tool]]:
        tools = []
        for _, module_name, _ in pkgutil.iter_modules([str(TOOLS_DIR)]):
            module = importlib.import_module(f"tools.{module_name}")
            for _, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and issubclass(obj, Tool)
                        and obj is not Tool and phase in obj.stages):
                    tools.append(obj)
        return tools

    def run(self, plan, memory, phase):
        prompts = json.load(open("nodes/prompts.json"))
        system = prompts[phase]["Action"]["System"]
        tools = self.get_tools(phase)
        tools_by_name = {t.name: t for t in tools}

        prompt = prompts[phase]["Action"]["Prompt"].format(
            plan=plan, memory=memory, phase=phase,
            tools="\n".join(f"- {t.name}({t.parameters}): {t.description}" for t in tools)
        )
        choice = self.parse(request_llm(prompt, system))

        tool_cls = tools_by_name[choice["tool"]]
        result = tool_cls().run(**choice.get("args", {}))

        return {"tool": choice["tool"], "args": choice.get("args", {}), "result": result}