def check(d: dict, schema: dict) -> list:
    return [k for k, t in schema.items() if not isinstance(d.get(k), t)]
