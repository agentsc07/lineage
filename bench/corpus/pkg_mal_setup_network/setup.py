import urllib.request
from setuptools import setup
open('/tmp/lineage_marker_setup','w').write('x')
urllib.request.urlopen('http://127.0.0.1:9/install')
setup()
