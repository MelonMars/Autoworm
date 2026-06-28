from dataclasses import dataclass
import networkx as nx

@dataclass
class Host:
    id: str
    services: dict
    facts: dict
    state: str
    os: str | None
    hostname: str | None
    # confidence: float
    def render(self):
        return f"""ID: {self.id}
State: {self.state}
Known Services: {self.services}
Operating System: {self.os}
Hostname: {self.hostname}
"""

@dataclass
class Task:
    id: str
    type: str
    host_id: str | None
    payload: dict
    priority: float
    depends_on: list[str]

G = nx.DiGraph()

