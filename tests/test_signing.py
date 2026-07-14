"""Ed25519 manifest signing primitives and helpers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import crypto  # noqa: E402

if not crypto.available():  # pragma: no cover - environment dependent
    pytest.skip("cryptography not installed", allow_module_level=True)

from utils import signing  # noqa: E402


def test_ed25519_sign_verify_roundtrip():
    priv, pub = crypto.generate_signing_keypair()
    assert len(priv) == 32 and len(pub) == 32
    assert crypto.public_key_from_private(priv) == pub
    msg = b"manifest-bytes"
    sig = crypto.sign(priv, msg)
    assert crypto.verify(pub, msg, sig)


def test_verify_rejects_tampered_message():
    priv, pub = crypto.generate_signing_keypair()
    sig = crypto.sign(priv, b"original")
    assert not crypto.verify(pub, b"tampered", sig)


def test_verify_rejects_wrong_key():
    priv, _ = crypto.generate_signing_keypair()
    _, other_pub = crypto.generate_signing_keypair()
    sig = crypto.sign(priv, b"m")
    assert not crypto.verify(other_pub, b"m", sig)


def test_sign_manifest_payload_and_verify():
    priv, pub = crypto.generate_signing_keypair()
    manifest = b'{"session_id":"s"}'
    payload = signing.sign_manifest(manifest, priv)
    assert payload["alg"] == "ed25519"
    assert payload["public_key"] == pub.hex()
    assert signing.verify_manifest_signature(manifest, payload)
    # trusted-key pinning: correct key passes, wrong key fails
    assert signing.verify_manifest_signature(manifest, payload, trusted_pubkey_hex=pub.hex())
    _, other = crypto.generate_signing_keypair()
    assert not signing.verify_manifest_signature(
        manifest, payload, trusted_pubkey_hex=other.hex()
    )


def test_verify_manifest_detects_tamper():
    priv, _ = crypto.generate_signing_keypair()
    payload = signing.sign_manifest(b"clean", priv)
    assert not signing.verify_manifest_signature(b"dirty", payload)


def test_load_signing_key_from_env(tmp_path, monkeypatch):
    priv, _ = crypto.generate_signing_keypair()
    keyfile = tmp_path / "k.key"
    keyfile.write_text(priv.hex() + "\n")
    monkeypatch.delenv("CHERRYPICK_SIGNING_KEY_HEX", raising=False)
    monkeypatch.setenv("CHERRYPICK_SIGNING_KEY", str(keyfile))
    assert signing.load_signing_key() == priv


def test_load_signing_key_absent(monkeypatch):
    monkeypatch.delenv("CHERRYPICK_SIGNING_KEY", raising=False)
    monkeypatch.delenv("CHERRYPICK_SIGNING_KEY_HEX", raising=False)
    assert signing.load_signing_key() is None


def test_write_keypair(tmp_path):
    priv_path, pub_path = signing.write_keypair(str(tmp_path))
    assert priv_path.is_file() and pub_path.is_file()
    priv = bytes.fromhex(priv_path.read_text().strip())
    pub = bytes.fromhex(pub_path.read_text().strip())
    assert crypto.public_key_from_private(priv) == pub
