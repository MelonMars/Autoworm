from tools.base import Tool

REGISTRY: dict[str, Tool] = {}

def register(t: Tool) -> Tool:
    REGISTRY[t.name] = t
    return t