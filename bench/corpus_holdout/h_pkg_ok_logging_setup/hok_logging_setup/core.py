import logging
import threading

_lock = threading.Lock()


def setup(level=logging.INFO):
    with _lock:
        logging.basicConfig(level=level)
