from setuptools import setup
from setuptools.command.install import install


class Post(install):
    def run(self):
        open('/tmp/lineage_marker_cmd', 'w').write('x')
        install.run(self)


setup(cmdclass={'install': Post})
