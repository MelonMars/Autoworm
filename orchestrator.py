from nodes import Plan, Action, Judge, Summarizer, Progress
from phases import phase_dict
from memory import Memory

class Agent:
    def __init__(self):
        self.PlanNode = Plan()
        self.JudgeNode = Judge()
        self.ActionNode = Action()
        self.SummarizerNode = Summarizer()
        self.ProgressNode = Progress()
        self.memory = Memory()

    def explore(self, phase, max_rounds=2, batch=3, attempts=3):
        for _ in range(max_rounds):
            self.memory.add_hypotheses(self.GenerateNode.run(self.memory, phase, batch))
            while (h := self.memory.next_open()) is not None:
                self.memory.activate(h)
                if self.pursue(phase, h, attempts):
                    return True

        return False

    def pursue(self, phase, h, attempts) -> bool:
        for _ in range(attempts):
            plan = self.PlanNode.run(...)
            judgement = self.JudgeNode.run(...)
            if judgement.decision == "reject":
                continue
            if judgement.decision == "revise":
                plan = judgement.revised_plan

            action = self.ActionNode.run(plan, self.memory, phase)
            self.memory.log_action(action["tool"], action["args"], action["result"])
            self.memory.add_observation(action["result"])
            summary = self.SummarizerNode.run(self.memory, action["result"], phase)
            self.memory.add_summary(summary)

            verdict = self.ProgressNode.run(phase, summary, self.memory)
            if verdict == "complete":
                h.status = "solved"
                return True
            if verdict == "failed":
                break
        h.status = "failed"
        self.memory.record_failure("exhausted attempts")
        return False