from dataclasses import dataclass
import networkx as nx

@dataclass
class Hypothesis:
    id: str
    description: str
    evidence: list[str]
    confidence: float
    failed_attempts: list[str]

@dataclass
class Host:
    id: str
    services: dict
    facts: dict
    state: str
    os: str | None
    hostname: str | None
    hypotheses: list[dict]
    ip: str | None
    foothold: dict | None
    vulnerabilities: dict
    source_host: str | None = None

    def render(self) -> str:
        return (f"host={self.id} ip={self.ip} os={self.os} hostname={self.hostname} "
                f"state={self.state} foothold={self.foothold} "
                f"services={self.services} facts={self.facts}")


@dataclass
class Task:
    id: str
    type: str
    host_id: str | None
    payload: dict
    priority: float
    depends_on: list[str]

@dataclass
class Campaign:
    graph: nx.DiGraph
    hosts: list[Host]

def build_working_memory(host: Host, max_facts=8) -> dict:
    wm = {
        "ip": host.ip,
        "hostname": host.hostname,
        "os": host.os,
        "services": host.services,
    }
    
    if isinstance(host.facts, dict):
        priority_keys = ["vulnerabilities", "auth_mechanism", "tech_stack", "framework", "server"]
        relevant_facts = {k: v for k, v in host.facts.items() if k in priority_keys}
        
        if len(relevant_facts) < max_facts:
            all_keys = list(host.facts.keys())
            for k in all_keys[-max_facts:]:
                if k not in relevant_facts:
                    relevant_facts[k] = host.facts[k]
                    
        wm["facts"] = relevant_facts
    else:
        wm["facts"] = host.facts

    return wm
