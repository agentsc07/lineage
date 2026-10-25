import stat

import pytest

from lineage.signing.ed25519 import sign_passport, verify_signed
from lineage.signing.keys import generate_keypair, key_id, load_private_key, load_public_key
from lineage.signing import sigstore_opt


def test_generate_and_load_keypair(tmp_path):
    kid = generate_keypair(tmp_path, "org")
    priv, pub = load_private_key(tmp_path / "org.key"), load_public_key(tmp_path / "org.pub")
    assert kid == key_id(pub) and len(kid) == 16
    assert priv.public_key().public_bytes_raw() == pub.public_bytes_raw()
    assert stat.S_IMODE((tmp_path / "org.key").stat().st_mode) == 0o600


def test_generate_refuses_to_overwrite(tmp_path):
    generate_keypair(tmp_path)
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path)


def test_sign_verify_roundtrip(tmp_path, sample_passport):
    generate_keypair(tmp_path)
    priv, pub = load_private_key(tmp_path / "default.key"), load_public_key(tmp_path / "default.pub")
    signed = sign_passport(sample_passport, priv, key_id(pub))
    assert signed.key_id == key_id(pub)
    assert verify_signed(signed, pub)


def test_tampered_passport_fails(tmp_path, sample_passport):
    generate_keypair(tmp_path)
    priv, pub = load_private_key(tmp_path / "default.key"), load_public_key(tmp_path / "default.pub")
    signed = sign_passport(sample_passport, priv, "k")
    signed.passport.predicate.risk_score = 99
    assert not verify_signed(signed, pub)


def test_wrong_key_and_garbage_signature_fail(tmp_path, sample_passport):
    generate_keypair(tmp_path, "a")
    generate_keypair(tmp_path, "b")
    signed = sign_passport(sample_passport, load_private_key(tmp_path / "a.key"), "a")
    assert not verify_signed(signed, load_public_key(tmp_path / "b.pub"))
    signed.signature = "!!notbase64!!"
    assert not verify_signed(signed, load_public_key(tmp_path / "a.pub"))


def test_sigstore_optional(sample_passport):
    if sigstore_opt.sigstore_available():
        pytest.skip("sigstore installed; keyless signing needs network/OIDC")
    assert sigstore_opt.sigstore_available() is False
    with pytest.raises(RuntimeError, match="sigstore"):
        sigstore_opt.sign_keyless(sample_passport)
