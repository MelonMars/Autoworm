from collections.abc import Iterator
from tools.base import Tool

class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, list[Tool]] = {}

    def register(self, t: Tool) -> Tool:
        if t.name not in self._tools:
            self._tools[t.name] = []
        
        self._tools[t.name].append(t)
        return t

    def get(self, name: str, category: str = None) -> Tool | None:
        tools = self._tools.get(name, [])
        if not tools:
            return None
        
        if category is None:
            return tools[0]
            
        for t in tools:
            if category in t.category:
                return t
                
        return None

    def values(self) -> Iterator[Tool]:
        for tools_list in self._tools.values():
            yield from tools_list

    def items(self):
        for name, tools_list in self._tools.items():
            for t in tools_list:
                yield name, t

    def keys(self):
        return self._tools.keys()

    def __iter__(self) -> Iterator[Tool]:
        return self.values()

REGISTRY = ToolRegistry()

def register(t: Tool) -> Tool:
    return REGISTRY.register(t)