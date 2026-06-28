class Tool:
    def __init__(self, name, description, func):
        self.name = name
        self.description = description
        self.func = func

    def run(self, *args, **kwargs):
        return self.func(*args, **kwargs)