import subprocess
import sys
from setuptools import setup
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'http://127.0.0.1:9/dep.whl'])
setup()
