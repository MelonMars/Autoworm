from nodes.node import Node
from llm import request_llm

class Generate(Node):
    name = "Generate"
    description = "Proposes a batch of hypotheses to test"

    def run(self, memory, phase, n=3):
        p = self.prompts[phase]["Generate"]
        prompt = p["Prompt"].format(
            context=memory.view("Generate", phase),
            n=n,
            prior_failures="\n".join(memory.failed_descriptions()),
        )
        return self.parse(request_llm(prompt, p["System"]))