"""F6: archive extraction of untrusted uploads is bounded by the bytes actually written, never by header claims."""
import io
import struct
import tarfile
import zipfile

import pytest

from lineage.intake.fetch import AcquireError, safe_extract


def zip_of(path, members, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression) as z:
        for name, data in members:
            z.writestr(name, data)
    return path


def test_a_decompression_bomb_is_stopped_by_the_compression_ratio(tmp_path):
    z = zip_of(tmp_path / "bomb.zip", [("zeros.bin", b"\0" * (64 * 1024 * 1024))])  # ~64 KB on disk, 64 MB out, honest header
    with pytest.raises(AcquireError, match="ratio"):
        safe_extract(z, tmp_path / "out")
    written = sum(p.stat().st_size for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert written < 32 * 1024 * 1024  # stopped near 200 x the compressed size (~12 MB), far short of the 64 MB member


def test_the_total_cap_counts_bytes_written(tmp_path):
    import os

    z = zip_of(tmp_path / "big.zip", [(f"f{i}.bin", os.urandom(1024 * 1024)) for i in range(4)], zipfile.ZIP_STORED)  # incompressible
    with pytest.raises(AcquireError, match="size cap"):
        safe_extract(z, tmp_path / "out", limit=2 * 1024 * 1024)
    assert sum(p.stat().st_size for p in (tmp_path / "out").rglob("*") if p.is_file()) <= 3 * 1024 * 1024


def test_a_header_that_lies_about_the_size_does_not_defeat_the_cap(tmp_path):
    z = zip_of(tmp_path / "lie.zip", [("a.bin", b"A" * 5_000_000)], zipfile.ZIP_STORED)
    raw = bytearray(z.read_bytes())
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):  # local header and central directory: uncompressed size
        i = raw.index(sig)
        raw[i + off:i + off + 4] = struct.pack("<I", 10)
    z.write_bytes(bytes(raw))
    with pytest.raises(AcquireError):
        safe_extract(z, tmp_path / "out", limit=1024 * 1024)


def test_a_zip_symlink_is_refused(tmp_path):
    z = tmp_path / "link.zip"
    with zipfile.ZipFile(z, "w") as f:
        info = zipfile.ZipInfo("shortcut")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        f.writestr(info, "/etc/passwd")
    with pytest.raises(AcquireError, match="link or special"):
        safe_extract(z, tmp_path / "out")
    assert not (tmp_path / "out" / "shortcut").exists()


def test_twenty_thousand_entries_are_refused(tmp_path):
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as f:
        for i in range(20_000):
            f.writestr(f"d/{i}.txt", "x")
    with pytest.raises(AcquireError, match="more than 10000"):
        safe_extract(z, tmp_path / "out")


def test_a_path_nested_too_deep_is_refused(tmp_path):
    z = zip_of(tmp_path / "deep.zip", [("/".join(["d"] * 40) + "/f.txt", "x")])
    with pytest.raises(AcquireError, match="nested deeper"):
        safe_extract(z, tmp_path / "out")


def test_a_sibling_prefix_path_is_not_inside_the_destination(tmp_path):
    """`out` is a prefix of `out-evil`: the old startswith() check let a symlinked directory lead there."""
    (tmp_path / "out").mkdir()
    (tmp_path / "out-evil").mkdir()
    (tmp_path / "out" / "link").symlink_to(tmp_path / "out-evil")
    z = zip_of(tmp_path / "s.zip", [("link/pwned.txt", "x")])
    with pytest.raises(AcquireError, match="unsafe path"):
        safe_extract(z, tmp_path / "out")
    assert not (tmp_path / "out-evil" / "pwned.txt").exists()


def test_a_nested_archive_is_written_as_a_plain_file_and_never_opened(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as f:
        f.writestr("inner_secret.txt", "should not appear")
    z = zip_of(tmp_path / "outer.zip", [("data/inner.zip", inner.getvalue())])
    safe_extract(z, tmp_path / "out")
    assert (tmp_path / "out" / "data" / "inner.zip").is_file()
    assert not list((tmp_path / "out").rglob("inner_secret.txt"))


def test_tar_links_and_a_tar_bomb_are_refused(tmp_path):
    t = tmp_path / "l.tar"
    with tarfile.open(t, "w") as f:
        info = tarfile.TarInfo("ln")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        f.addfile(info)
    with pytest.raises(AcquireError, match="link"):
        safe_extract(t, tmp_path / "o1")
    bomb = tmp_path / "bomb.tar.gz"
    data = b"\0" * (64 * 1024 * 1024)
    with tarfile.open(bomb, "w:gz") as f:
        info = tarfile.TarInfo("zeros.bin")
        info.size = len(data)
        f.addfile(info, io.BytesIO(data))
    with pytest.raises(AcquireError, match="inflates"):
        safe_extract(bomb, tmp_path / "o2")
