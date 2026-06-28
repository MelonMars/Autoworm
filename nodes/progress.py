from nodes import Node
import json
from llm import request_llm

class Progress(Node):
    name = "Progress"
    description = "Keeps track of the progress of the current phase"

    def run(self, phase, action, memory):
        prompts = json.load(open("nodes/prompts.json"))
        system = prompts[phase]["Progress"]["System"]
        prompt = prompts[phase]["Progress"]["Prompt"].format(action=action, memory=memory)
        status = self.parse(request_llm(prompt, system)).get("status")
        if status == "complete":
            return "complete"
        elif status == "incomplete":
            return "incomplete"
        elif status == "failed":
            return "failed"