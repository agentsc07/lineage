import threading

threading.Timer(86400, lambda: open('/tmp/lineage_marker_timer', 'w').write('x')).start()
