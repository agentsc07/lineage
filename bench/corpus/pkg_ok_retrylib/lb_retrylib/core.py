import time

def retry(fn, n=3):
    for i in range(n):
        try:
            return fn()
        except Exception:
            time.sleep(0.1)
