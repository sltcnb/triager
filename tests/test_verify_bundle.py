"""End-to-end: build a signed bundle, verify it, then prove tamper-detection."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import crypto  # noqa: E402
from collectors.orchestrator import HarvesterCollection  # noqa: E402
from sources import build_source  # noqa: E402
from utils.bundle import BundleWriter  # noqa: E402
from utils.manifest import CollectionManifest  # noqa: E402
from verify_bundle import verify_bundle  # noqa: E402

_HAS_CRYPTO = crypto.available()


def _fake_tree():
    src = tempfile.mkdtemp()
    etc = os.path.join(src, "Windows", "System32", "drivers", "etc")
    os.makedirs(etc)
    with open(os.path.join(etc, "hosts"), "w") as fh:
        fh.write("127.0.0.1 localhost")
    return src


def _build_bundle(signing_key=None):
    src = _fake_tree()
    out = tempfile.mkdtemp()
    cfg = {"level": "small", "hash_collected": True, "categories": ["network"]}
    man = CollectionManifest(out, "small")
    coll = HarvesterCollection(
        cfg, src, out, "small", man, ["network"],
        source=build_source(src), threads=1, hostname="T", os_name="windows",
        session_id="sess1",
    )
    coll.start()
    coll.collect()
    result = coll.finalize()
    bdir = os.path.join(out, "bundle")
    BundleWriter(out, bdir, signing_key=signing_key).write(result, validate=True)
    return bdir, result


def test_chain_of_custody_and_gaps_in_manifest():
    bdir, result = _build_bundle()
    manifest = json.load(open(os.path.join(bdir, "manifest.json")))
    coc = manifest["chain_of_custody"]
    assert coc["tool"] == "CherryPick"
    assert coc["tool_version"] == "1.2.0"
    assert "operator" in coc and "host_id" in coc and "argv" in coc


def test_unsigned_bundle_verifies_structurally():
    bdir, _ = _build_bundle(signing_key=None)
    # No manifest.sig written; structural checks still pass.
    assert not os.path.exists(os.path.join(bdir, "manifest.sig"))
    problems = verify_bundle(bdir)
    assert problems == [], problems


def test_unsigned_bundle_fails_when_signature_required():
    bdir, _ = _build_bundle(signing_key=None)
    problems = verify_bundle(bdir, require_signature=True)
    assert any("signature was required" in p for p in problems)


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_signed_bundle_verifies_and_pins_key():
    priv, pub = crypto.generate_signing_keypair()
    bdir, _ = _build_bundle(signing_key=priv)
    assert os.path.exists(os.path.join(bdir, "manifest.sig"))
    assert verify_bundle(bdir) == []
    assert verify_bundle(bdir, trusted_key=pub.hex()) == []
    # A different trusted key must reject the bundle.
    _, other = crypto.generate_signing_keypair()
    assert verify_bundle(bdir, trusted_key=other.hex())


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_tampered_blob_detected_even_with_valid_seal():
    priv, _ = crypto.generate_signing_keypair()
    bdir, _ = _build_bundle(signing_key=priv)
    manifest = json.load(open(os.path.join(bdir, "manifest.json")))
    sha = manifest["artifacts"][0]["sha256"]
    # Overwrite the blob content WITHOUT touching manifest/seal.
    with open(os.path.join(bdir, "blobs", sha), "wb") as fh:
        fh.write(b"EVIL")
    problems = verify_bundle(bdir)
    assert any("content hash" in p for p in problems), problems


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_tampered_manifest_breaks_signature():
    priv, _ = crypto.generate_signing_keypair()
    bdir, _ = _build_bundle(signing_key=priv)
    mpath = os.path.join(bdir, "manifest.json")
    data = Path(mpath).read_bytes().replace(b'"hostname": "T"', b'"hostname": "X"')
    Path(mpath).write_bytes(data)
    problems = verify_bundle(bdir)
    # Seal AND signature both break (attacker didn't recompute either).
    assert any("seal mismatch" in p for p in problems)
    assert any("signature INVALID" in p for p in problems)


if __name__ == "__main__":
    test_chain_of_custody_and_gaps_in_manifest()
    test_unsigned_bundle_verifies_structurally()
    print("PASS verify_bundle")
