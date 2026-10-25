"""LineageBench corpus: builds, is labelled, and every malicious payload is inert (CLAUDE.md rule)."""
import re
from collections import Counter

from bench.build_corpus import build_corpus

ALLOWED_URL = re.compile(r"https?://(127\.0\.0\.1:9|api\.github\.com|api\.weather\.gov|in-toto\.io|lineage\.dev)")


def test_corpus_labelled_and_inert(tmp_path):
    items = build_corpus(tmp_path / "c", bank_dir=tmp_path / "nobank", weightspace=tmp_path / "none.json")
    c = Counter((i["category"], i["label"]) for i in items)
    assert c[("tampered_weights", "malicious")] == 10 and c[("pickle_payload", "malicious")] == 5
    assert c[("package_payload", "malicious")] == 10 and c[("mcp_tool_poisoning", "malicious")] == 5
    assert all(i["label"] in ("malicious", "benign") for i in items)
    for f in (tmp_path / "c").rglob("*"):
        if not f.is_file() or f.suffix in (".safetensors", ".bin", ".key", ".pub"):
            continue
        text = f.read_text(errors="ignore")
        for url in re.findall(r"https?://[^\s'\"<>)]+", text):
            assert ALLOWED_URL.match(url), (f, url)
        for path in re.findall(r"/tmp/\S+", text):
            assert path.startswith("/tmp/lineage_marker_"), (f, path)
