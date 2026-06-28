import json, re

class Node:
    name: str = ""
    description: str = ""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def run(self, *args, **kwargs):
        raise NotImplementedError("Subclasses must implement this method.")
    
    def parse(self, raw: str) -> dict:
        raw = re.sub(r"{.*?}", "{}", raw)
        print("Received:", raw)
        return json.loads(raw)