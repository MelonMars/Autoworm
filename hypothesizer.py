from memory import Host, Hypothesis
from llm import request_llm, extract_json

HYPOTHESIZER_SYSTEM = """You are a hypothesis generator for an authorized penetration test. You're job is to generate hypotheses about potential vulnerabilities in a host, based on the host's known facts, its relationships to other hosts/services, and any inferences or signals from the analysis stage.

You are given the host's known facts, its edges to other hosts/services, and any inferences or signals from the analysis stage. Reason across them: combine separate facts into conclusions, flag what's missing, and surface anything security-relevant.

Schema: {
    "Hypotheses": [
        {
            "description": str, // a concise statement of the hypothesis
            "evidence": [str], // a list of facts, inferences, or signals that support this hypothesis
            "confidence": float, // a float 0-1: how likely this hypothesis is to be true
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

def generate_hypothses(host: Host, inferences: list[dict], signals: list[dict]):
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
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=512
        )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"Hypotheses": [], "Further Investigation": [], "_raw": raw}

    data.setdefault("Hypotheses", [])
    data.setdefault("Further Investigation", [])
    return data