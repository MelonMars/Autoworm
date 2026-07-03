import json
import re

from llm import request_llm, extract_json
from memory import Host
from tools.base import Tool

NORMALIZE_SYSTEM_SEARCH = """You convert raw security tool output into ONE JSON object.
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

def normalize_tool_output_search(tool: Tool, output: str, host: Host):
    prompt = f"""
Tool: {tool.name}\n"
Description: {tool.description}\n\n"
Current host info: {host.render()}\n\n"
Raw Output: {output}"""
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM_SEARCH,
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

NORMALIZE_SYSTEM_FOOTHOLD = """You convert raw exploit tool output into ONE JSON object.
Your primary goal is to extract CLAIMS of newly established access (footholds). 
Output only the JSON. No prose, no markdown fences.

Schema:
{
  "facts": {},             // standard facts extracted (e.g., vulnerability confirmed)
  "new_edges": [],         // standard relationships
  "foothold_claims": [     // IF the output suggests a shell/access was obtained, list it here
    {
      "type": "webshell|reverse_shell|bind_shell|ssh_key|cron_job|suid_binary",
      "details": {},       // Specifics needed to interact with the claim (see examples)
      "raw_evidence": ""   // The exact sentence from the output that makes this claim
    }
  ],
  "confidence": 0.0        // float 0-1: how complete/correct this extraction is
}

Details schema by type:
- webshell: {"url": "http://...", "param": "cmd"}
- reverse_shell: {"ip": "listener_ip", "port": 4444}
- bind_shell: {"ip": "target_ip", "port": 5555}
- ssh_key: {"user": "root", "key_path": "/root/.ssh/authorized_keys"}
- suid_binary: {"path": "/usr/bin/find"}

CRITICAL: If the output shows an ERROR, "FAILED", or "DENIED", foothold_claims MUST be an empty list [].
Only add a claim if the text explicitly states a shell was spawned, a file was written, or a connection was made.

Example 1 (Webshell):
{
  "facts": {"vulnerability": "unauthenticated_rce"},
  "new_edges": [],
  "foothold_claims": [{"type": "webshell", "details": {"url": "http://10.0.0.1/uploads/shell.php", "param": "cmd"}, "raw_evidence": "[+] Webshell planted at /var/www/html/uploads/shell.php"}],
  "confidence": 0.95
}

Example 2 (Failed Exploit):
{
  "facts": {},
  "new_edges": [],
  "foothold_claims": [],
  "confidence": 0.9
}"""

def normalize_tool_output_foothold(tool: Tool, output: str, host: Host):
    prompt = f"""Tool: {tool.name}
Description: {tool.description}

Current host info: {host.render()}

Raw Output: {output}"""
    
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM_FOOTHOLD,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=512
        )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"facts": {}, "new_edges": [], "foothold_claims": [], "confidence": 0.0, "_raw": raw}

    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    data.setdefault("foothold_claims", [])
    data.setdefault("confidence", 0.0)
    return data

NORMALIZE_SYSTEM_SEARCHSPLOIT = """You convert raw searchsploit output into ONE JSON object.
Output only the JSON. No prose, no markdown fences.

Schema:
{
  "vulnerabilities": {
    "CVE-XXXX-XXXXX": {
      "exploits": [
        {"title": "...", "path": "...", "platform": "...", "type": "exploit|shellcode|dos|local|remote|webapps"}
      ]
    }
  },
  "unmatched_exploits": [
    {"title": "...", "path": "...", "platform": "...", "type": "..."}
  ],
  "confidence": 0.0
}

Rules:
- If an exploit title references a CVE ID (e.g. CVE-2021-44228), place it under that CVE key in vulnerabilities.
- If an exploit has no CVE reference, place it in unmatched_exploits.
- Extract platform and type from the searchsploit columns.
- If no exploits found, return empty vulnerabilities, empty unmatched_exploits, and low confidence.
- Multiple exploits for the same CVE go into the same exploits list."""


def normalize_searchsploit(output: str, tool: Tool, host: Host) -> dict:
    prompt = f"""Tool: {tool.name}
Description: {tool.description}

Current host info: {host.facts}

Raw Output: {output}"""

    raw = request_llm(
        prompt,
        system=NORMALIZE_SYSTEM_SEARCHSPLOIT,
        enable_thinking=False,
        do_sample=False,
        max_new_tokens=512,
    )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"facts": {}, "new_edges": [], "vulnerabilities": {}, "confidence": 0.0, "_raw": raw}

    data.setdefault("vulnerabilities", {})
    data.setdefault("confidence", 0.0)
    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    return data


def normalize_cve_response(output: str) -> dict:
    try:
        if isinstance(output, dict):
            raw_json = output.get("stdout", "")
        else:
            raw_json = output

        if isinstance(raw_json, str):
            raw_json = re.sub(r'^\s*\n', '', raw_json)

        data = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError, AttributeError):
        return {"facts": {}, "new_edges": [], "vulnerabilities": {}, "confidence": 0.0, "_raw": str(output)}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"facts": {}, "new_edges": [], "vulnerabilities": {}, "confidence": 0.0}

    cve_entry = vulns[0].get("cve", {})
    cve_id = cve_entry.get("id", "UNKNOWN")

    descriptions = cve_entry.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    metrics = cve_entry.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            break

    cvss_score = cvss_data.get("baseScore") if cvss_data else None
    cvss_vector = cvss_data.get("vectorString") if cvss_data else None

    weaknesses = cve_entry.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            cwe_ids.append(desc.get("value", ""))

    cpe_matches = []
    for node in cve_entry.get("configurations", []):
        for n in node.get("nodes", []):
            for cpe in n.get("cpeMatch", []):
                if cpe.get("criteria"):
                    cpe_matches.append(cpe["criteria"])

    references = []
    for ref in cve_entry.get("references", []):
        references.append(ref.get("url", ""))

    vuln_record = {
        "description": description,
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe": cwe_ids,
        "affected_products": cpe_matches,
        "references": references,
        "exploits": [],
    }

    return {
        "facts": {},
        "new_edges": [],
        "vulnerabilities": {cve_id: vuln_record},
        "confidence": 1.0,
    }


def normalize_tool_output(tool: Tool, output, host: Host, phase: str) -> dict:
    if tool.category == "search":
        if tool.name == "cve_search_api":
            return normalize_cve_response(output)
        elif tool.name == "exploitdb_search":
            return normalize_searchsploit(output, tool, host)
        else:
            return normalize_tool_output_search(tool, output, host)

    if phase == "establish_foothold":
        return normalize_tool_output_foothold(tool, output, host)

    return normalize_tool_output_search(tool, output, host)
