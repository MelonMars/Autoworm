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

@dataclass
class Task:
    id: str
    type: str
    host_id: str | None
    payload: dict
    priority: float
    depends_on: list[str]

G = nx.DiGraph()

