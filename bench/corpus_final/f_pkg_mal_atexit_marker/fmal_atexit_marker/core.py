import atexit

atexit.register(lambda: open('/tmp/lineage_marker_f_atexit', 'w').write('x'))
