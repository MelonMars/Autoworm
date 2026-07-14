import json
import re

from llm import request_llm, extract_json
from memory import Host
from tools.base import Tool
from pydantic import BaseModel, Field
from typing import Optional

class Service(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    more_info: Optional[str] = None

class Edge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    type: str

class NormalizeResult(BaseModel):
    facts: dict = {}
    services: dict[str, Service] = {}
    new_edges: list[Edge] = []
    confidence: float = 0.0

def sanitize_normalizer_output(raw_data: dict) -> dict:
    if not isinstance(raw_data, dict):
        return raw_data

    facts = raw_data.get("facts", {})
    if not isinstance(facts, dict):
        facts = {}
        raw_data["facts"] = facts

    if "services" in facts and isinstance(facts["services"], dict):
        top_level_services = raw_data.get("services", {})
        if not isinstance(top_level_services, dict):
            top_level_services = {}
        top_level_services.update(facts.pop("services"))
        raw_data["services"] = top_level_services

    services = raw_data.get("services", {})
    if isinstance(services, dict):
        for key in ["os", "hostname", "ip"]:
            if key in services:
                facts[key] = services.pop(key)

    return raw_data

def truncate_raw_output_for_llm(raw_output_str: str, max_length=1500) -> str:
    if len(raw_output_str) <= max_length:
        return raw_output_str
        
    body_pattern = r'("body"\s*:\s*")(.+?)("(?:\s*[,}]))'
    match = re.search(body_pattern, raw_output_str, re.DOTALL)
    
    if match:
        full_body = match.group(2)
        if len(full_body) > 300:
            truncated_body = full_body[:300] + "... [TRUNCATED_BY_ORCHESTRATOR]"
            raw_output_str = (raw_output_str[:match.start(2)] + 
                              truncated_body + 
                              raw_output_str[match.end(2):])
            
    if len(raw_output_str) > max_length:
        raw_output_str = raw_output_str[:max_length] + "\n... [OUTPUT TRUNCATED] "
        
    return raw_output_str

NORMALIZE_SYSTEM_SEARCH = """You convert raw security tool output into ONE JSON object.
Output only the JSON. No prose, no markdown fences. Do not repeat the host information, just analyze the tool output.

Schema:
{
  "facts": {},        // structured data extracted from the output; lowercase keys; null for unknown values
  "services": {       // if the output mentions a service, list it here with details
        "port": {"name": "...", "version": "...", "more_info": "..."},
        "port2": {"name": "...", "version": "...", "more_info": "..."},
        ...
    },
  "new_edges": [],    // relationships, e.g. {"from": "host", "to": "ssh", "type": "runs_service"}
  "confidence": 0.0   // float 0-1: how complete/correct this extraction is
}

Example:
{
  "facts": {

  },
  "services": {
      "22": {"name": "ssh", "version": "8.2"},
      "80": {"name": "http", "version": "Apache/2.4.41"}
  },
  "new_edges": [
    {"from": "host", "to": "ssh", "type": "runs_service"}
  ],
  "confidence": 0.87
}

Make sure new_edges is not inside of facts.

If the output is an error or empty, return empty facts, empty new_edges, and low confidence. The allowable keys for facts are services, vulnerabilities, os, hostname, and any other relevant information. The values should be structured as dictionaries or lists as appropriate."""

def normalize_tool_output_search(tool: Tool, output: str, host: Host):
    safe_output_str = truncate_raw_output_for_llm(output, max_length=1500)
    prompt = f"""
Tool: {tool.name}
Description: {tool.description}
Current host info: {host.render()}
Raw Output: {safe_output_str}"""
    print("Normalizing tool output with prompt:", prompt)
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM_SEARCH,
            enable_thinking=False,
            schema=NormalizeResult,
            do_sample=False,
            max_new_tokens=2048
        )
    
    print("Normalizer LLM output:", raw)

    try:
        data = extract_json(raw)
    except (ValueError, json.JSONDecodeError):
        return {"facts": {}, "new_edges": [], "confidence": 0.0, "services": {}, "_raw": raw}

    data = sanitize_normalizer_output(data)
    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    data.setdefault("confidence", 0.0)
    data.setdefault("services", {})

    print("Sanitized normalizer output:", data)

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


def _get_stdout(output) -> str:
    """Extract stdout string from either a dict or raw string output."""
    if isinstance(output, dict):
        return output.get("stdout", "")
    return str(output) if output else ""


NORMALIZE_SYSTEM_WEB_SEARCH = """You convert web search results into structured security intelligence.
Output only the JSON. No prose, no markdown fences.

Schema:
{
  "facts": {},              // structured findings about the target software/service
  "new_edges": [],          // relationships discovered
  "vulnerabilities": {      // CVE IDs and their details found in search results
    "CVE-XXXX-XXXXX": {
      "description": "...",
      "exploit_available": true/false,
      "msf_module": "exploit/..." or null,
      "cwe": ["CWE-XXX"],
      "references": ["url1", "url2"]
    }
  },
  "confidence": 0.0
}

Rules:
- Extract CVE IDs mentioned in any result title or snippet.
- Note if an exploit, PoC, or Metasploit module is referenced.
- Extract CWE IDs if mentioned.
- Extract default credentials, misconfigurations, or logic flaws described.
- If results mention a specific software version vulnerability, include it in facts.
- If no security-relevant info found, return empty structures and low confidence."""


def normalize_web_search(output, tool: Tool, host: Host) -> dict:
    raw = _get_stdout(output)
    prompt = f"""Tool: {tool.name}
Description: {tool.description}

Current host info: {host.render()}

Raw Output: {raw}"""

    llm_raw = request_llm(
        prompt,
        system=NORMALIZE_SYSTEM_WEB_SEARCH,
        enable_thinking=False,
        do_sample=False,
        max_new_tokens=1024,
    )
    try:
        data = extract_json(llm_raw)
    except (ValueError, Exception):
        return {"facts": {}, "new_edges": [], "vulnerabilities": {},
                "confidence": 0.0, "_raw": llm_raw}

    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    data.setdefault("vulnerabilities", {})
    data.setdefault("confidence", 0.0)
    return data

NORMALIZE_SYSTEM_HTTP = """You convert HTTP request/response data into structured security observations.
Output only the JSON. No prose, no markdown fences.

Schema:
{
  "facts": {
    "http_status": 200,
    "server": "Apache/2.4.41",
    "framework": "...",
    "auth_mechanism": "...",
    "tech_stack": ["..."],
    "interesting_headers": {"header_name": "value"},
    "error_messages": ["..."],
    "redirects": ["..."]
  },
  "services": {
    "port": {"name": "http", "version": "...", "more_info": "..."}
  },
  "new_edges": [],
  "confidence": 0.0
}

Rules:
- Extract server software, framework (from headers like X-Powered-By, Server, or page content).
- Identify authentication mechanisms (login forms, auth headers, cookie-based sessions).
- Note error messages that reveal tech stack or internal details.
- Capture any interesting headers (CSP, CORS, X-Frame-Options, etc.).
- If status is 401/403/302, note what auth mechanism is expected.
- If body contains login form, admin panel, or API endpoint, note it in facts.
- Low confidence for generic pages, high for security-relevant discoveries."""


def normalize_http_response(output, tool: Tool, host: Host) -> dict:
    raw = _get_stdout(output)
    prompt = f"""Tool: {tool.name}
Description: {tool.description}

Current host info: {host.render()}

Raw Output: {raw[:3000]}"""

    llm_raw = request_llm(
        prompt,
        system=NORMALIZE_SYSTEM_HTTP,
        enable_thinking=False,
        do_sample=False,
        max_new_tokens=512,
    )
    try:
        data = extract_json(llm_raw)
    except (ValueError, Exception):
        return {"facts": {}, "services": {}, "new_edges": [],
                "confidence": 0.0, "_raw": llm_raw}

    data.setdefault("facts", {})
    data.setdefault("services", {})
    data.setdefault("new_edges", [])
    data.setdefault("confidence", 0.0)
    return data

NORMALIZE_SYSTEM_VALIDATE = """You analyze raw security tool output from a VULNERABILITY VALIDATION scan (e.g., nmap --script vuln, nikto, specialized CVE checkers). 
Output only the JSON. No prose, no markdown fences.

Schema:
{
  "facts": {
    "vuln_verified": false,    // MUST be true ONLY if the output explicitly states the host is VULNERABLE, EXPLOITABLE, or confirms a specific CVE/weakness.
    "vuln_details": "",        // If vuln_verified is true, extract the specific vulnerability description here.
    "vuln_id": "",             // e.g., "CVE-2009-1151" or "CWE-123" if mentioned.
    "extra_info": ""           // Any other context (e.g., "Requires authentication", "Only affects SSLv2")
  },
  "services": {},              // Leave empty unless a NEW service was discovered during this specific scan.
  "new_edges": [],
  "confidence": 0.0            // How certain you are that the tool ran correctly and the output is parseable.
}

RULES:
- Look for keywords like "VULNERABLE", "EXPLOIT", "CVE-", "exploitable", "vuln".
- If the output says "SAFE", "Not vulnerable", or just shows open ports without vuln data, "vuln_verified" MUST be false.
- Do not guess. If the tool errored out, return confidence 0.0 and vuln_verified false."""

def normalize_tool_output_validate(tool: Tool, output: str, host: Host) -> dict:
    prompt = f"""
Tool: {tool.name}
Description: {tool.description}
Current host info: {host.render()}
Raw Output: {output}"""
    
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM_VALIDATE,
            enable_thinking=False,
            max_new_tokens=1024
        )
    
    try:
        data = extract_json(raw)
    except Exception:
        return {"facts": {"vuln_verified": False, "vuln_details": "Failed to parse validation output"}, "services": {}, "new_edges": [], "confidence": 0.0}

    data.setdefault("facts", {})
    data["facts"].setdefault("vuln_verified", False)
    data["facts"].setdefault("vuln_details", "")
    data["facts"].setdefault("vuln_id", "")
    data.setdefault("services", {})
    data.setdefault("new_edges", [])
    data.setdefault("confidence", 0.0)
    
    return data

NORMALIZE_SYSTEM_MSF = """You convert msfconsole output into structured JSON.
Output only JSON.

Schema:
{
  "facts": {
    "vuln_verified": false,
    "vuln_id": "",
    "extra_info": ""
  },
  "services": {},
  "vulnerabilities": {},
  "foothold_claims": [],
  "confidence": 0.0
}

Rules:
- foothold_claims: copy through any session-opened events from the raw output.
  Each claim: {"type": "meterpreter"|"msf_shell", "details": {...}}
- vuln_verified=true ONLY if msfconsole reports "[+] <target> - Host is likely VULNERABLE" or similar.
- Capture any new service banners msf identified (smb_version, ssh_version etc.) in services.
"""

def normalize_msf_output(tool, output, host):
    raw = output.get("stdout", "") if isinstance(output, dict) else str(output)
    claims = output.get("foothold_claims", []) if isinstance(output, dict) else []
    prompt = f"Tool: {tool.name}\nRaw Output:\n{raw[:6000]}"
    llm_raw = request_llm(prompt, system=NORMALIZE_SYSTEM_MSF,
                          enable_thinking=False, do_sample=False, max_new_tokens=1024)
    try:
        data = extract_json(llm_raw)
    except Exception:
        data = {}
    data.setdefault("facts", {})
    data.setdefault("services", {})
    data.setdefault("vulnerabilities", {})
    data.setdefault("foothold_claims", [])
    data["foothold_claims"] = claims or data["foothold_claims"]
    data.setdefault("confidence", 0.5)
    return data

def normalize_tool_output(tool: Tool, output, host: Host, phase: str) -> dict:

    if tool.category == "search":
        if tool.name == "cve_search_api":
            return normalize_cve_response(output)
        elif tool.name == "exploitdb_search":
            return normalize_searchsploit(output, tool, host)
        else:
            return normalize_tool_output_search(tool, output, host)
    elif phase == "validate_vuln":
        return normalize_tool_output_validate(tool, output, host)
    elif tool.name == "http_request":
        return normalize_http_response(output, tool, host)
    elif tool.name == "msf_module" or tool.name == "msfvenom":
        return normalize_msf_output(tool, output, host)
    return normalize_tool_output_search(tool, output, host)

def check_opportunity(normalized_result: dict, host: Host) -> dict | None:
    if not normalized_result.get("ok", True):
        return None

    claims = normalized_result.get("foothold_claims", [])
    if claims:
        return {"type": "claim", "data": claims[0]}

    facts = normalized_result.get("facts", {})
    if "ssh_private_key" in facts or "password" in facts:
        return {
            "type": "inferred_ssh", 
            "data": {"type": "ssh_key", "details": facts}
        }

    return None

