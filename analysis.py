from memory import Host, DiGraph
from llm import request_llm, extract_json

ANALYZE_SYSTEM = """You analyze a host's accumulated state from a security perspective and output ONE JSON object. Output only the JSON. No prose, no markdown fences.

You are given the host's known facts and its edges to other hosts/services. Reason across them: combine separate facts into conclusions, flag what's missing, and surface anything security-relevant.

Schema:
{
  "facts": {},        // observed, directly evidenced state. Restate/consolidate; do not invent.
  "inferences": [],   // conclusions DERIVED by combining facts, not directly observed. Each: {"claim": str, "based_on": [str], "confidence": 0.0}
  "unknowns": [],     // gaps worth probing next, phrased as concrete next actions. Each: {"question": str, "why": str}
  "signals": []       // security-relevant indicators: risk, exposure, anomaly. Each: {"signal": str, "severity": "low|medium|high", "rationale": str}
}

Rules:
- A fact is something the data shows. An inference is something you concluded from facts; if you can point at a single fact, it's a fact, not an inference.
- Every inference must cite the facts it rests on in "based_on".
- Do not fabricate versions, ports, or hosts not present in the input.
- If a category has nothing, return it empty. Do not pad."""

def render_proximal(G, host_id):
    out_edges = list(G.out_edges(host_id, data=True))
    in_edges = list(G.in_edges(host_id, data=True))

    if not out_edges and not in_edges:
        return f"{host_id} has no known relationships."

    lines = [f"Relationships for {host_id}:"]
    for u, v, d in out_edges:
        lines.append(f"  {u} --{d.get('type', '?')}--> {v}")
    for u, v, d in in_edges:
        lines.append(f"  {u} --{d.get('type', '?')}--> {v}")
    return "\n".join(lines)

def analyze(host: Host, G: DiGraph):
    prompt = f"""
Known Facts: {host.facts}
Discovered Services: {host.services}
OS: {host.os}
Hostname: {host.hostname}

{render_proximal(G, host.id)}"""
    raw = request_llm(
            prompt,
            system=ANALYZE_SYSTEM,
            enable_thinking=False,
            do_sample=False,
            max_new_tokens=256
        )
    try:
        data = extract_json(raw)
    except (ValueError, Exception):
        return {"facts": {}, "inferences": [], "unknowns": [], "signals": [], "_raw": raw}

    data.setdefault("facts", {})
    data.setdefault("inferences", [])
    data.setdefault("unknowns", [])
    data.setdefault("signals", [])

    return data
