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
    hypotheses: list[Hypothesis]
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

