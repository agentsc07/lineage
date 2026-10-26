import time

def timed(fn):
    t = time.time()
    fn()
    return time.time() - t
