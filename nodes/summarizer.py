from nodes.node import Node
import json
from llm import request_llm

class Summarizer(Node):
    name = "Summarizer"
    description = "Create a summary of the tool output"

    def run(self, memory, output, phase):
        prompts = json.load(open("nodes/prompts.json"))
        system = prompts[phase]["Summarizer"]["System"]
        prompt = prompts[phase]["Summarizer"]["Prompt"].format(memory=memory, output=output)
        summary = self.parse(request_llm(prompt, system))

        return summary