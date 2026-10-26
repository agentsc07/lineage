import argparse


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--n', type=int, default=1)
    return p.parse_args(argv).n
