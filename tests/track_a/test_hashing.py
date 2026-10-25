import hashlib
import json
import struct
from pathlib import Path

import numpy as np
import pytest
from safetensors import safe_open

from lineage.hashing.files import hash_file, hash_tree
from lineage.hashing.merkle import merkle_proof, merkle_root, verify_proof
from lineage.hashing.tensors import hash_gguf, hash_safetensors


def test_hash_file_matches_hashlib(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"x" * 100_000)
    assert hash_file(p, chunk_size=4096) == hashlib.sha256(b"x" * 100_000).hexdigest()


def test_hash_tree_relative_posix_keys(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.txt").write_bytes(b"b")
    (tmp_path / "a.txt").write_bytes(b"a")
    tree = hash_tree(tmp_path, workers=2)
    assert set(tree) == {"a.txt", "d/b.txt"}
    assert tree["a.txt"] == hashlib.sha256(b"a").hexdigest()


def test_hash_tree_single_file(tmp_path):
    p = tmp_path / "m.bin"
    p.write_bytes(b"zz")
    assert hash_tree(p) == {"m.bin": hashlib.sha256(b"zz").hexdigest()}


def test_safetensors_tensor_hashes_match_raw_bytes(tiny_model):
    path = tiny_model / "model.safetensors"
    hashes = hash_safetensors(path)
    assert set(hashes) == {"layers.0.weight", "layers.0.bias", "layers.1.weight", "layers.1.bias"}
    with safe_open(str(path), "np") as f:
        arr = f.get_tensor("layers.1.bias")
    assert hashes["layers.1.bias"] == hashlib.sha256(arr.tobytes()).hexdigest()


def test_safetensors_child_differs_only_in_perturbed(tiny_model, tiny_model_child):
    a = hash_safetensors(tiny_model / "model.safetensors")
    b = hash_safetensors(tiny_model_child / "model.safetensors")
    assert {k for k in a if a[k] != b[k]} == {"layers.1.weight"}


def test_safetensors_rejects_bad_header(tmp_path):
    p = tmp_path / "bad.safetensors"
    p.write_bytes(struct.pack("<Q", 10**12) + b"{}")
    with pytest.raises(ValueError):
        hash_safetensors(p)


def _write_gguf(path: Path, tensors: dict[str, np.ndarray], alignment: int = 32) -> None:
    def s(x: str) -> bytes:
        b = x.encode()
        return struct.pack("<Q", len(b)) + b

    meta = s("general.alignment") + struct.pack("<I", 4) + struct.pack("<I", alignment)
    infos, blobs, off = b"", [], 0
    for name, arr in tensors.items():
        assert arr.dtype == np.float32
        infos += s(name) + struct.pack("<I", arr.ndim)
        infos += b"".join(struct.pack("<Q", d) for d in arr.shape[::-1])
        infos += struct.pack("<I", 0) + struct.pack("<Q", off)  # type 0 = F32
        raw = arr.tobytes()
        pad = (-len(raw)) % alignment
        blobs.append(raw + b"\0" * pad)
        off += len(raw) + pad
    head = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", len(tensors)) + struct.pack("<Q", 1) + meta + infos
    head += b"\0" * ((-len(head)) % alignment)
    path.write_bytes(head + b"".join(blobs))


def test_gguf_tensor_hashes(tmp_path):
    rng = np.random.default_rng(1)
    t = {"blk.0.w": rng.standard_normal((3, 5)).astype(np.float32), "blk.0.b": rng.standard_normal(7).astype(np.float32)}
    p = tmp_path / "m.gguf"
    _write_gguf(p, t)
    h = hash_gguf(p)
    assert h == {k: hashlib.sha256(v.tobytes()).hexdigest() for k, v in t.items()}


def test_gguf_rejects_non_gguf(tmp_path):
    p = tmp_path / "x.gguf"
    p.write_bytes(b"NOPE" + b"\0" * 64)
    with pytest.raises(ValueError):
        hash_gguf(p)


def test_merkle_root_deterministic_and_order_independent():
    a = {"x": "1" * 64, "y": "2" * 64, "z": "3" * 64}
    assert merkle_root(a) == merkle_root(dict(reversed(list(a.items()))))
    assert merkle_root(a) != merkle_root({**a, "z": "4" * 64})
    assert merkle_root({}) == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8])
def test_merkle_proofs_verify(n):
    leaves = {f"f{i}": hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)}
    root = merkle_root(leaves)
    for name, digest in leaves.items():
        assert verify_proof(name, digest, merkle_proof(leaves, name), root, leaves)
    assert not verify_proof("f0", "0" * 64, merkle_proof(leaves, "f0"), root, leaves)
