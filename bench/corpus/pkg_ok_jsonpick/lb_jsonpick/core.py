import json

def dump(o, p):
    open(p, 'w').write(json.dumps(o))
