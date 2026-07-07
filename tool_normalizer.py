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

  },
  "services": {
      "22": {"name": "ssh", "version": "8.2"}
  },
  "new_edges": [
    {"from": "host", "to": "ssh", "type": "runs_service"}
  ],
  "confidence": 0.87
}

Make sure new_edges is not inside of facts.

If the output is an error or empty, return empty facts, empty new_edges, and low confidence. The allowable keys for facts are services, vulnerabilities, os, hostname, and any other relevant information. The values should be structured as dictionaries or lists as appropriate."""

def normalize_tool_output_search(tool: Tool, output: str, host: Host):
    prompt = f"""
Tool: {tool.name}
Description: {tool.description}
Current host info: {host.render()}
Raw Output: {output}"""
    print("Normalizing tool output with prompt:", prompt)
    raw = request_llm(
            prompt,
            system=NORMALIZE_SYSTEM_SEARCH,
            enable_thinking=False,
            schema=NormalizeResult,
            do_sample=False,
            max_new_tokens=1024
        )
    try:
        data = extract_json(raw)
    except (ValueError, json.JSONDecodeError):
        return {"facts": {}, "new_edges": [], "confidence": 0.0, "services": {}, "_raw": raw}

    data.setdefault("facts", {})
    data.setdefault("new_edges", [])
    data.setdefault("confidence", 0.0)
    data.setdefault("services", {})
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


def _get_stdout(output) -> str:
    """Extract stdout string from either a dict or raw string output."""
    if isinstance(output, dict):
        return output.get("stdout", "")
    return str(output) if output else ""


# ---------------------------------------------------------------------------
# MSF Search normalizer — deterministic JSON parse, no LLM needed
# ---------------------------------------------------------------------------

def normalize_msf_search(output, tool: Tool, host: Host) -> dict:
    raw = _get_stdout(output).strip()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"facts": {}, "new_edges": [], "confidence": 0.0, "_raw": raw}

    modules = data.get("modules", [])
    facts = {
        "msf_search": {
            "query": data.get("query", ""),
            "module_type": data.get("module_type", ""),
            "total_matches": data.get("total_matches", len(modules)),
        }
    }
    edges = []
    for m in modules:
        fullname = m.get("fullname", m.get("path", ""))
        edges.append({"from": "host", "to": fullname, "type": "has_msf_module"})

    return {"facts": facts, "new_edges": edges, "confidence": 0.95}


# ---------------------------------------------------------------------------
# MSF Exploit normalizer — structured JSON parse + foothold claims from sessions
# ---------------------------------------------------------------------------

def normalize_msf_exploit(output, tool: Tool, host: Host) -> dict:
    raw = _get_stdout(output).strip()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"facts": {}, "new_edges": [], "foothold_claims": [],
                "confidence": 0.0, "_raw": raw}

    facts = {"msf_exploit": {
        "module_path": data.get("module_path", ""),
        "status": data.get("status", ""),
        "description": data.get("description", "")[:300],
        "execute_result": data.get("execute_result", ""),
    }}

    edges = []
    if data.get("status") == "executed":
        edges.append({"from": "host", "to": data.get("module_path", ""),
                      "type": "exploit_attempted"})

    # Extract foothold claims from active sessions
    foothold_claims = []
    sessions = data.get("active_sessions", {})
    if isinstance(sessions, dict) and sessions:
        for sid, sinfo in sessions.items():
            session_type = sinfo.get("type", "unknown")
            claim_type = "meterpreter" if "meterpreter" in session_type else "msf_shell"
            foothold_claims.append({
                "type": claim_type,
                "details": {
                    "session_id": str(sid),
                    "type": session_type,
                    "tunnel_peer": sinfo.get("tunnel_peer", ""),
                },
                "raw_evidence": f"Session {sid} ({session_type}) active after exploit execution",
            })

    return {
        "facts": facts,
        "new_edges": edges,
        "foothold_claims": foothold_claims,
        "confidence": 0.95,
    }


# ---------------------------------------------------------------------------
# MSF Sessions normalizer — structured JSON parse
# ---------------------------------------------------------------------------

def normalize_msf_sessions(output, tool: Tool, host: Host) -> dict:
    raw = _get_stdout(output).strip()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"facts": {}, "new_edges": [], "confidence": 0.0, "_raw": raw}

    action = data.get("action", "")
    facts = {"msf_session": {"action": action}}

    edges = []
    if action == "list":
        sessions = data.get("sessions", {})
        facts["msf_session"]["active_count"] = data.get("count", len(sessions))
        facts["msf_session"]["sessions"] = sessions
        for sid in sessions:
            edges.append({"from": "host", "to": f"session_{sid}", "type": "active_session"})
    elif action in ("write", "write_and_read", "read"):
        facts["msf_session"]["session_id"] = data.get("session_id", "")
        facts["msf_session"]["command"] = data.get("command", "")
        facts["msf_session"]["output"] = data.get("output", "")[:2000]

    return {"facts": facts, "new_edges": edges, "confidence": 0.95}


# ---------------------------------------------------------------------------
# Web search normalizer — LLM extracts security-relevant intelligence
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HTTP response normalizer — LLM extracts security signals
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Exploit exec normalizer — reuses foothold normalizer (same claim pattern)
# ---------------------------------------------------------------------------

def normalize_exploit_exec(output, tool: Tool, host: Host) -> dict:
    """Custom exploit output has the same success/failure pattern as foothold tools."""
    return normalize_tool_output_foothold(tool, _get_stdout(output), host)


# ---------------------------------------------------------------------------
# Master routing
# ---------------------------------------------------------------------------

def normalize_tool_output(tool: Tool, output, host: Host, phase: str) -> dict:
    # --- Search category tools ---
    if tool.category == "search":
        if tool.name == "cve_search_api":
            return normalize_cve_response(output)
        elif tool.name == "exploitdb_search":
            return normalize_searchsploit(output, tool, host)
        elif tool.name == "msf_search":
            return normalize_msf_search(output, tool, host)
        elif tool.name == "web_search":
            return normalize_web_search(output, tool, host)
        else:
            return normalize_tool_output_search(tool, output, host)

    # --- Named tool dispatch (before phase fallback) ---
    if tool.name == "msf_exploit":
        return normalize_msf_exploit(output, tool, host)
    elif tool.name == "msf_sessions":
        return normalize_msf_sessions(output, tool, host)
    elif tool.name == "http_request":
        return normalize_http_response(output, tool, host)
    elif tool.name == "exploit_exec":
        return normalize_exploit_exec(output, tool, host)

    # --- Phase-based fallback ---
    if phase == "establish_foothold":
        return normalize_tool_output_foothold(tool, output, host)

    return normalize_tool_output_search(tool, output, host)
