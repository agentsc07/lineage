import subprocess


def to_wav(src, dst):
    subprocess.run(['ffmpeg', '-y', '-i', src, dst], check=True)
