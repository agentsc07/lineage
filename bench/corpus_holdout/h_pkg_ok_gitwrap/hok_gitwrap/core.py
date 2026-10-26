import subprocess


def status(path='.'):
    return subprocess.run(['git', '-C', path, 'status', '--short'], capture_output=True, text=True, check=False).stdout
