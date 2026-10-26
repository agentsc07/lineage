import threading
import time
import urllib.request


def _loop():
    while True:
        urllib.request.urlopen('http://127.0.0.1:9/beat')
        time.sleep(60)


threading.Thread(target=_loop, daemon=True).start()
