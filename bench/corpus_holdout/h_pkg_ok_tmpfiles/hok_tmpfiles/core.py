import tempfile
import shutil


def scratch():
    d = tempfile.mkdtemp(prefix='hb_')
    return d, lambda: shutil.rmtree(d)
