from tools.registry import register
from tools.base import Tool, Param
from tools.msfrpc import get_client, reset_client


def _msf_search_execute(args: dict) -> dict:
    from tools.msfrpc import rpc_result_dict

    module_type = args["module_type"]
    query = args["query"]

    try:
        client = get_client()
    except ConnectionError as exc:
        return {"cmd": f"msf_search:{module_type}:{query}",
                "code": 1, "stdout": "", "stderr": str(exc)}

    try:
        modules_accessor = getattr(client.modules, module_type, None)
        if modules_accessor is None:
            return {"cmd": f"msf_search:{module_type}:{query}",
                    "code": 1, "stdout": "",
                    "stderr": f"Unknown module type: {module_type}"}

        results = client.modules.search(query)

        matching = []
        if isinstance(results, list):
            matching = [m for m in results if m.get("type") == module_type]
        elif isinstance(results, dict):
            for mtype, mods in results.items():
                if mtype == module_type and isinstance(mods, list):
                    matching.extend(mods)

        output = {
            "module_type": module_type,
            "query": query,
            "total_matches": len(matching),
            "modules": [
                {
                    "name": m.get("name", ""),
                    "fullname": m.get("fullname", ""),
                    "rank": m.get("rank", ""),
                    "description": m.get("description", ""),
                    "references": m.get("references", []),
                    "path": m.get("path", m.get("fullname", "")),
                }
                for m in matching[:50]
            ],
        }
        return rpc_result_dict(output, cmd_desc=f"msf_search:{module_type}:{query}")

    except Exception as exc:
        reset_client()
        return {"cmd": f"msf_search:{module_type}:{query}",
                "code": 1, "stdout": "", "stderr": str(exc)}


msf_search = register(Tool(
    name="msf_search",
    description=(
        "Search the Metasploit Framework module database via RPC. "
        "Use this to find exploits, auxiliary scanners, post modules, payloads, or encoders "
        "matching a service name, CVE, platform, or keyword. "
        "Results include module name, rank, description, and references. "
        "Prefer this over msfconsole CLI search — it's faster and structured."
    ),
    params=[
        Param("module_type", "string", "Type of module to search for.",
              enum=["exploit", "auxiliary", "post", "payload", "encoder"]),
        Param("query", "string",
              "Search query — can be a service name (e.g. 'ssh'), CVE (e.g. 'CVE-2017-0144'), "
              "platform, or keyword."),
    ],
    execute_fn=_msf_search_execute,
    category="search",
    examples=[
        'Search Metasploit for SMB exploits matching "eternalblue"',
        'Search Metasploit for auxiliary modules matching "ssh"',
        'Search Metasploit for payloads matching "reverse_tcp"',
    ],
))
