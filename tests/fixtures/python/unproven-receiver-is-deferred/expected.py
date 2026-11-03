class ConfigShim:
    def load(self, raw):
        return {"raw": raw}


yaml = ConfigShim()

settings = yaml.load("a: 1")
