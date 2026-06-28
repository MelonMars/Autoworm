import importlib
import inspect
import pkgutil

from nodes.node import Node
from tools.tool import Tool
from llm import request_llm


class Plan(Node):
    name = "Plan"
    description = "Reasons over a hypothesis and prior failures to produce a single plan for Action."
    MAX_STEPS = 6
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

    