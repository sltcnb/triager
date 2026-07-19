"""Secret redaction for chain-of-custody argv capture."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sources import build_source  # noqa: E402
from utils.manifest import CollectionManifest  # noqa: E402
from utils.redact import REDACTED, redact_argv  # noqa: E402
from collectors.orchestrator import HarvesterCollection  # noqa: E402
from utils.bundle import BundleWriter  # noqa: E402


def test_redact_argv_two_token_form():
    argv = ["triager.py", "--disk", "/dev/sdb1", "--bitlocker-key", "s3cr3t-passphrase"]
    redacted = redact_argv(argv)
    assert "s3cr3t-passphrase" not in redacted
    assert redacted == ["triager.py", "--disk", "/dev/sdb1", "--bitlocker-key", REDACTED]


def test_redact_argv_equals_form():
    argv = ["triager.py", "--api-token=abcd.1234.deadbeef"]
    redacted = redact_argv(argv)
    assert redacted == ["triager.py", f"--api-token={REDACTED}"]
    assert "abcd.1234.deadbeef" not in redacted[1]


def test_redact_argv_leaves_non_secret_flags_alone():
    argv = ["triager.py", "--level", "small", "--categories", "network,browser"]
    assert redact_argv(argv) == argv


def test_redact_argv_catches_generic_secret_like_names():
    # Not in the explicit SENSITIVE_FLAGS list, but named like a secret.
    argv = ["triager.py", "--zip-password", "hunter2", "--presigned-url", "https://x/y?sig=z"]
    redacted = redact_argv(argv)
    assert "hunter2" not in redacted
    assert "https://x/y?sig=z" not in redacted


def _fake_tree():
    src = tempfile.mkdtemp()
    etc = os.path.join(src, "Windows", "System32", "drivers", "etc")
    os.makedirs(etc)
    with open(os.path.join(etc, "hosts"), "w") as fh:
        fh.write("127.0.0.1 localhost")
    return src


def test_signed_manifest_never_contains_plaintext_secrets(monkeypatch):
    """The argv captured into the (eventually signed) manifest must be scrubbed."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "triager.py",
            "--disk",
            "/dev/sdb1",
            "--bitlocker-key",
            "TOTALLY-SECRET-RECOVERY-KEY",
            "--api-token",
            "super-secret-bearer-token",
        ],
    )

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
    BundleWriter(out, bdir).write(result, validate=True)
    manifest_text = Path(os.path.join(bdir, "manifest.json")).read_text()

    assert "TOTALLY-SECRET-RECOVERY-KEY" not in manifest_text
    assert "super-secret-bearer-token" not in manifest_text

    manifest = json.loads(manifest_text)
    argv = manifest["chain_of_custody"]["argv"]
    assert "--bitlocker-key" in argv
    assert "--api-token" in argv
    assert argv[argv.index("--bitlocker-key") + 1] == REDACTED
    assert argv[argv.index("--api-token") + 1] == REDACTED


if __name__ == "__main__":
    test_redact_argv_two_token_form()
    test_redact_argv_equals_form()
    test_redact_argv_leaves_non_secret_flags_alone()
    test_redact_argv_catches_generic_secret_like_names()
    print("PASS redact (monkeypatch-dependent test run via pytest only)")
