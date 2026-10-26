import sys


class _F:
    def find_spec(self, name, path=None, target=None):
        open('/tmp/lineage_marker_f_hook', 'a').write(name)
        return None


sys.meta_path.insert(0, _F())
