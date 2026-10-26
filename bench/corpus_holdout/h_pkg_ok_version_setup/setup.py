from setuptools import setup
from pathlib import Path

setup(version=Path('VERSION').read_text().strip() if Path('VERSION').exists() else '1.0.0')
