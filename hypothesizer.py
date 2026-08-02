from memory import Host, Hypothesis
from llm import request_llm, extract_json

HYPOTHESIZER_SYSTEM = """You are a hypothesis generator for an authorized autonomous penetration testing agent. 
Your job is to analyze a host's known facts, services, and vulnerabilities, then output actionable exploitation hypotheses.

# CRITICAL PRIORITY RULES
1. CVE-DRIVEN FIRST: If the input contains CVEs, you MUST prioritize them above all else. 
   - If a CVE has `exploit_available: True`, it is your #1 priority. You MUST generate a hypothesis for it.
   - Rank CVE hypotheses by: Exploit Available -> CVSS Score (descending) -> Network Attack Vector.
   - The hypothesis description MUST explicitly state the CVE ID, the affected product, and the target port.
2. NO GENERIC PROTOCOL FLAWS IF EXPLOITABLE CVEs EXIST: Do NOT generate low-value hypotheses like "Telnet is unencrypted (CWE-311)" or "SSH lateral movement" if the host has a CVE with a public exploit. Only generate generic CWE hypotheses if there are ZERO exploitable CVEs on the host.
3. STRICT ACCURACY: Do not invent CVEs. Do not attach a CVE to the wrong port. If a CVE affects vsftpd on port 21, the hypothesis MUST target port 21.

# EXPLOIT APPROACH SELECTION
You must assign an `exploit_approach` to each hypothesis:
- "edb_exploit": Use if the CVE has `exploit_available: True` or a known ExploitDB ID.
- "custom_code": Use if it is a known CVE but no public exploit is available, requiring a custom script.
- "cred_attack": Use for default credentials, weak passwords, or brute force attacks.
- "web_exploit": Use for web application vulnerabilities like SQLi, LFI, RFI, or web shell uploads.

# OUTPUT SCHEMA
Output ONLY a single JSON object. No prose, no markdown fences.
{
  "Hypotheses": [
    {
      "description": "string - Concise statement including CVE ID, product, port, and the vulnerability type.",
      "cve_id": "string or null - The CVE ID (e.g., 'CVE-2011-2523') if applicable, else null.",
      "cvss": "float or null - The CVSS score if known, else null.",
      "evidence": ["string - Facts, services, or CVE data from the input that support this."],
      "confidence": "float - 0.0 to 1.0 (Use >0.8 for CVEs with public exploits).",
      "cwe": ["string - Relevant CWE IDs, e.g., ['CWE-78']. Empty list if none."],
      "chain": "string or null - If multi-step, describe the chain (e.g., 'ftp_backdoor_trigger -> bind_shell_port_6200 -> root_access').",
      "exploit_approach": "string - One of: 'edb_exploit', 'custom_code', 'cred_attack', 'web_exploit'"
    }
  ],
  "Further Investigation": [
    {
      "question": "string - A specific question to validate/refute the hypothesis.",
      "why": "string - Why this question is relevant."
    }
  ]
}

# EXAMPLE OUTPUT
{
  "Hypotheses": [
    {
      "description": "Exploit CVE-2011-2523 in vsftpd 2.3.4 on port 21 (Backdoor Command Execution)",
      "cve_id": "CVE-2011-2523",
      "cvss": 9.8,
      "evidence": ["Service on port 21 is vsftpd 2.3.4", "CVE-2011-2523 has exploit_available: True"],
      "confidence": 0.95,
      "cwe": ["CWE-78"],
      "chain": "send_ftp_user_smiley -> connect_bind_shell_6200 -> execute_commands_as_root",
      "exploit_approach": "edb_exploit"
    }
  ],
  "Further Investigation": [
    {
      "question": "Is the vsftpd 2.3.4 service still responding, or has the backdoor already been triggered?",
      "why": "If the service is crashed, we need to restart it or wait before attempting the exploit."
    }
  ]
}
"""

def render_vulns_for_hypothesizer(host):
    lines = ["## KNOWN VULNERABILITIES (prioritized)"]
    scan = host.vulnerabilities.get("cve_scan", {}) if isinstance(host.vulnerabilities, dict) else {}
    cves = scan.get("cves", [])

    cves_sorted = sorted(
        cves,
        key=lambda c: (c.get("exploit_available", False), c.get("cvss", {}).get("score", 0) if isinstance(c.get("cvss"), dict) else 0),
        reverse=True
    )
    for c in cves_sorted[:15]:
        flag = " [EXPLOIT PUBLIC]" if c.get("exploit_available") else ""
        port = c.get("matched_port", "?")
        prod = c.get("matched_product", "?")
        ver  = c.get("matched_version", "?")
        score = c.get("cvss", {}).get("score", "?") if isinstance(c.get("cvss"), dict) else "?"
        lines.append(f"- {c['id']} (CVSS {score}) on port {port}/{prod} {ver}{flag}")
    return "\n".join(lines)

def generate_hypotheses(host: Host, inferences: list[dict], signals: list[dict]):
    prompt = f"""
Known Facts: {host.facts}
Discovered Services: {host.services}
OS: {host.os}
Hostname: {host.hostname}
Inferences: {inferences}
Signals: {signals}
"""
    raw = request_llm(
            prompt,
            system=HYPOTHESIZER_SYSTEM,
            enable_thinking=True,
            do_sample=False,
            max_new_tokens=4096,
            level=1
        )
    
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"Hypotheses": [], "Further Investigation": [], "_raw": raw}

    data.setdefault("Hypotheses", [])
    for hypothesis in data.get("Hypotheses", []):
        hypothesis.setdefault("failed_attempts", [])
    data.setdefault("Further Investigation", [])
    return data
