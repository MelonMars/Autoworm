from llm import request_llm, extract_json
from memory import Host, Task, G
from tools.tool import Tool

NORMALIZE_SYSTEM = """You convert raw security tool output into ONE JSON object.
Output only the JSON. No prose, no markdown fences. Do not repeat the host information, just analyze the tool output.

Schema:
{
  "facts": {},        // structured data extracted from the output; lowercase keys; null for unknown values
  "new_edges": [],    // relationships, e.g. {"from": "host", "to": "ssh", "type": "runs_service"}
  "confidence": 0.0   // float 0-1: how complete/correct this extraction is
}

Example:
{
  "facts": {
    "services": {
      "22": {"name": "ssh", "version": "8.2"}
    }
  },
  "new_edges": [],
  "confidence": 0.87
}

If the output is an error or empty, return empty facts, empty new_edges, and low confidence."""

def normalize_tool_output(tool: Tool, output: str, host: Host):
    # Do we need host info?
    prompt = f"""
Tool: {tool.name}\n"
Description: {tool.description}\n\n"
Current host info: {host.render()}\n\n"
Raw Output: {output}"""
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=256
        )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"facts": {}, "new_edges": [], "confidence": 0.0, "_raw": raw}

    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    data.setdefault("confidence", 0.0)
    return data

def apply_update(host, update):
    for k, v in update.get("facts", {}).items():
        host.facts[k] = v
    for edge in update.get("new_edges", []):
        if "from" not in edge or "to" not in edge:
            continue
        G.add_edge(edge["from"], edge["to"], type=edge.get("type", ""))

if __name__ == "__main__":
    from tools.nmap import nmap
    tool = nmap()
    print(normalize_tool_output(tool, tool.test_run("192.168.1.3")))

