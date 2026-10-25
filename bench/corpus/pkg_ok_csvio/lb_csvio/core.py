import csv

def rows(p):
    with open(p) as f:
        return list(csv.DictReader(f))
