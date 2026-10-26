import json


def word_count(text):
    return json.dumps(json.loads(text), indent=2)
