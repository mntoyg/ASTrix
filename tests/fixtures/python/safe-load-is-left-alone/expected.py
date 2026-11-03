import yaml

RAW = "a: 1"

first = yaml.safe_load(RAW)
second = yaml.load(RAW, Loader=yaml.SafeLoader)
third = yaml.load(RAW, Loader=yaml.CSafeLoader)
fourth = yaml.dump({"a": 1})
