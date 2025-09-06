from providers import Provider

class Pyauth:
    def __init__(self,provider:Provider):
        self._provider = provider