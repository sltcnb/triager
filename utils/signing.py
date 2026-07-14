"""
Bundle manifest signing — chain-of-custody tamper-evidence for CherryPick.

The bundle's ``bundle.sha256`` only *seals* the manifest: anyone who edits a
blob, updates its hash in ``manifest.json`` and recomputes the seal produces a
"valid" bundle. That is integrity against corruption, not against tampering.

This module adds a keyed **Ed25519 detached signature** over the exact manifest
bytes. Because every artifact's SHA-256 lives in the manifest, a valid signature
transitively attests every blob. Verification needs only the agent's public key,
so a bundle can be checked independently of the collection host or the server.

Signing key resolution (first hit wins):

* ``CHERRYPICK_SIGNING_KEY``     — path to a raw (32-byte) or hex (64-char)
                                   Ed25519 private key.
* ``CHERRYPICK_SIGNING_KEY_HEX`` — the hex private key inline (CI / ephemeral).

If neither is set the bundle is written **UNSIGNED** and the caller is expected
to warn loudly — an unsigned forensic bundle is not court-defensible.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import crypto
from collectors.artifact_collector import now_iso

logger = logging.getLogger(__name__)

SIG_ALG = "ed25519"
SIG_FILENAME = "manifest.sig"


def _decode_key(data: bytes) -> bytes:
    """Accept a raw 32-byte key or a 64-char hex encoding; return raw 32 bytes."""
    stripped = data.strip()
    if len(stripped) == 64:
        try:
            return bytes.fromhex(stripped.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
    if len(data) == 32:
        return data
    if len(stripped) == 32:
        return stripped
    raise ValueError(
        f"signing key must be 32 raw bytes or 64 hex chars, got {len(stripped)} bytes"
    )


def load_signing_key() -> Optional[bytes]:
    """Return the raw Ed25519 private key from the environment, or None."""
    inline = os.environ.get("CHERRYPICK_SIGNING_KEY_HEX")
    if inline:
        return _decode_key(inline.encode("ascii"))
    path = os.environ.get("CHERRYPICK_SIGNING_KEY")
    if path:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"CHERRYPICK_SIGNING_KEY not found: {path}")
        return _decode_key(p.read_bytes())
    return None


def sign_manifest(manifest_bytes: bytes, private_key: bytes) -> dict:
    """Sign the exact manifest bytes; return the ``manifest.sig`` payload dict."""
    pub = crypto.public_key_from_private(private_key)
    signature = crypto.sign(private_key, manifest_bytes)
    return {
        "alg": SIG_ALG,
        "signed_at": now_iso(),
        "public_key": pub.hex(),
        "signature": signature.hex(),
        "target": "manifest.json",
    }


def verify_manifest_signature(
    manifest_bytes: bytes, sig_payload: dict, *, trusted_pubkey_hex: Optional[str] = None
) -> bool:
    """Verify a ``manifest.sig`` payload against the manifest bytes.

    When ``trusted_pubkey_hex`` is given, the signature's embedded public key must
    equal it — otherwise a bundle self-signed by an unknown key would "verify".
    """
    if sig_payload.get("alg") != SIG_ALG:
        return False
    pub_hex = sig_payload.get("public_key", "")
    if trusted_pubkey_hex and pub_hex.lower() != trusted_pubkey_hex.lower():
        return False
    try:
        pub = bytes.fromhex(pub_hex)
        signature = bytes.fromhex(sig_payload.get("signature", ""))
    except ValueError:
        return False
    return crypto.verify(pub, manifest_bytes, signature)


def write_keypair(dest_dir: str, name: str = "cherrypick_signing") -> tuple[Path, Path]:
    """Generate an Ed25519 keypair, write ``<name>.key`` (0600) + ``<name>.pub``.

    Returns ``(private_path, public_path)``. The private key is hex-encoded.
    """
    priv, pub = crypto.generate_signing_keypair()
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    priv_path = dest / f"{name}.key"
    pub_path = dest / f"{name}.pub"
    priv_path.write_text(priv.hex() + "\n", encoding="utf-8")
    try:
        os.chmod(priv_path, 0o600)
    except OSError:  # pragma: no cover - non-POSIX
        pass
    pub_path.write_text(pub.hex() + "\n", encoding="utf-8")
    return priv_path, pub_path
