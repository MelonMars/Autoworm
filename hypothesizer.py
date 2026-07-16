from memory import Host, Hypothesis
from llm import request_llm, extract_json

HYPOTHESIZER_SYSTEM = """You are a hypothesis generator for an authorized penetration test. Your job is to generate hypotheses about potential vulnerabilities in a host, based on the host's known facts, its relationships to other hosts/services, and any inferences or signals from the analysis stage.

You are given the host's known facts, its edges to other hosts/services, and any inferences or signals from the analysis stage. Reason across them: combine separate facts into conclusions, flag what's missing, and surface anything security-relevant.

CWE CLASSES TO CONSIDER:
- CWE-284/CWE-862 (improper access control/authorization): Missing auth checks, IDOR, privilege escalation via parameter manipulation
- CWE-798 (hard-coded/default credentials): Default accounts,出厂密码, vendor default logins
- CWE-287 (improper authentication): Weak login, session fixation, auth bypass via parameter tampering
- CWE-22 (path traversal): File inclusion, directory traversal in web parameters
- CWE-89/CWE-78 (injection): SQL injection, command injection, template injection
- CWE-434 (unrestricted file upload): Web shell upload, executable upload
- CWE-250/CWE-269 (improper privilege management): SUID binaries, misconfigured sudoers, writable config files
- CWE-311/CWE-312 (sensitive data exposure): Credentials in config files, memory dumps, cleartext protocols
- CWE-77 (command injection): OS command injection through web parameters or service inputs

VULNERABILITY CHAINING:
- Think in multi-step chains, not just single vulnerabilities.
- Example: information disclosure → credential theft → SSH access → privilege escalation
- Example: web app auth bypass → admin panel → file upload → webshell → reverse shell
- Example: open service enumeration → default credentials → service exploitation → lateral movement
- When generating hypotheses, note what information or access each step would provide for the next step.

Keep in mind there may be more vulnerabilities than just CWEs, such as simple CVEs, misconfigurations, or logic flaws. Your goal is to generate hypotheses that could be tested in the next phase of the penetration test.
If a hypothesis does not have a corresponding CWE, leave the "cwe" field empty ([]). If a hypothesis is multi-step, describe the chain in the "chain" field.

Schema: {
    "Hypotheses": [
        {
            "description": str, // a concise statement of the hypothesis (can include chain steps)
            "evidence": [str], // a list of facts, inferences, or signals that support this hypothesis
            "confidence": float, // a float 0-1: how likely this hypothesis is to be true
            "cwe": [str], // relevant CWE IDs
            "chain": str or null, // if multi-step, describe the chain (e.g. "info_disclosure -> cred_theft -> ssh_access")
            "exploit_approach": str // high-level approach: "http_request", "exploit_exec", etc.
        },
        ...
    ],
    "Further Investigation": [
        {
            "question": str, // a specific question that could help validate or refute the hypothesis
            "why": str, // a brief explanation of why this question is relevant
        },
        ...
    ]
}
"""

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
            max_new_tokens=4096
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