from dataclasses import dataclass
from typing import Callable
import os

def current_privilege() -> str:
    return "root" if hasattr(os, "geteuid") and os.geteuid() == 0 else "user"

@dataclass
class Param:
    name: str
    type: str                       # "string", "integer", ...
    description: str
    required: bool = True
    enum: list | None = None        # items: "value" or ("value", "root")
    default_privilege: str = "user"

    def choices(self) -> dict[str, str]:
        """value -> required privilege"""
        if not self.enum:
            return {}
        out = {}
        for item in self.enum:
            if isinstance(item, tuple):
                val, priv = item
            else:
                val, priv = item, self.default_privilege
            out[val] = priv
        return out

    def enum_values(self) -> list[str] | None:
        return list(self.choices()) or None

@dataclass
class Tool:
    name: str
    description: str
    params: list[Param]
    build_command: Callable[[dict], list[str]]   # validated args -> argv

    def input_schema(self) -> dict:
        props, required = {}, []
        for p in self.params:
            s = {"type": p.type, "description": p.description}
            vals = p.enum_values()
            if vals:
                s["enum"] = vals
            props[p.name] = s
            if p.required:
                required.append(p.name)
        return {"type": "object", "properties": props, "required": required}

    def params_doc(self) -> str:
        lines = []
        for p in self.params:
            req = "required" if p.required else "optional"
            if p.enum:
                rendered = ", ".join(
                    f"{v}(root)" if pr == "root" else v
                    for v, pr in p.choices().items()
                )
                lines.append(f"- {p.name} ({p.type}, {req}): one of {rendered}. {p.description}")
            else:
                lines.append(f"- {p.name} ({p.type}, {req}): {p.description}")
        return "\n".join(lines)

    def required_privilege(self, args: dict) -> str:
        for p in self.params:
            val = args.get(p.name)
            if val is not None and p.choices().get(val) == "root":
                return "root"
        return "user"
    