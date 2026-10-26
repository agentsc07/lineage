import functools
import time


def retry(n=3, wait=0.1):
    def deco(fn):
        @functools.wraps(fn)
        def run(*a, **k):
            for i in range(n):
                try:
                    return fn(*a, **k)
                except Exception:
                    if i == n - 1:
                        raise
                    time.sleep(wait)
        return run
    return deco
