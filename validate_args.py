def validate_args(args: dict, tool) -> str | None:
    names = {p.name for p in tool.params}
    for extra in set(args) - names:
        return f"unknown argument {extra!r}"
    for p in tool.params:
        if p.required and p.name not in args:
            return f"missing required {p.name!r}"
        if p.name in args and p.enum and args[p.name] not in p.enum_values():
            return f"{p.name}={args[p.name]!r} not in {p.enum_values()}"
    return None
