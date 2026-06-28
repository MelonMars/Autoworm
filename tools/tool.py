class Tool:
    name: str = ""
    description: str = ""
    stages: list[str] = []
    kind: str = "action"

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def run(self, *args, **kwargs):
        raise NotImplementedError("Subclasses must implement this method.")