from dataclasses import dataclass

@dataclass
class Hypothesis:
    description: str
    observations: list[str]
    summaries: list[str]
    failures: list[str]
    status: str = "open"

@dataclass
class Machine:
    machine_info: str
    machine_discovery_steps: list[str]
    hypotheses: list[Hypothesis]

@dataclass
class Memory:
    machines: list[Machine]
    phase: str
    identity: str
    current_task: str
    hints: list[str]
    action_history: list[str]
    active_machine: Machine | None
    active_hypothesis: int | None = None

    @property
    def hypothesis(self) -> Hypothesis | None:
        hs = self.active_machine.hypotheses
        return hs[self.active_hypothesis] if self.active_hypothesis is not None and hs else None

    def recent_actions(self, n=5):
        return "/n".join(self.action_history[-n:])
    
    def open_hypotheses(self, m: Machine) -> str:
        live = [h for h in m.hypotheses if len(h.failures) < 3]
        return "\n".join(h.render("compact") for h in live)
    
    def add_hypothesis(self, h: Hypothesis, m: Machine):
        m.hypotheses.append(h)

    def add_failure(self, h: Hypothesis, failure: str):
        h.failures.append(failure)
    
    def log_action(self, tool, args, result):
        self.action_history.append(f"{tool}({args}) -> {str(result)[:120]}")

    def add_observation(self, obs):
        if self.hypothesis: self.hypothesis.observations.append(obs)

    def add_summary(self, s):
        if self.hypothesis: self.hypothesis.summaries.append(s)

    def record_failure(self, reason):
        if self.hypothesis: self.hypothesis.failures.append(reason)

    def new_hypothesis(self, m: Machine, description):
        m.hypotheses.append(Hypothesis(description, [], [], []))
        self.active_hypothesis = len(self.machine.hypotheses) - 1
    
    def add_hypotheses(self, m: Machine, descriptions: list[str]):
        for d in descriptions:
            m.hypotheses.append(Hypothesis(d, [], [], []))
    
    def next_open(self, m: Machine) -> Hypothesis | None:
        return next((h for h in m.hypotheses if h.status == "open"), None)
    
    def activate(self, h: Hypothesis, m: Machine):
        self.active_hypothesis = m.hypotheses.index(h)

    def failed_descriptions(self, m: Machine) -> list[str]:
        return [h.description for h in m.hypotheses if len(h.failures) >= 3]


if __name__ == "__main__":
    hypothesis = Hypothesis(
        description="Test hypothesis",
        observations=["Observation 1", "Observation 2"],
        summaries=["Summary 1", "Summary 2"],
        failures=["Failure 1"]
    )
    machine = Machine(
        machine_info="Test machine",
        machine_discovery_steps=["Step 1", "Step 2"],
        hypotheses=[hypothesis]
    )
    print(Memory([machine], "test", "test", "test", ["test"], ["test"], machine).open_hypotheses(machine))