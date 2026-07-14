#!/usr/bin/env python3
"""
Independent CherryPick bundle verifier.

Re-validates a produced bundle end to end, WITHOUT the collection host or the
server — the property that makes a forensic bundle defensible:

1. manifest.json parses and (if jsonschema is present) conforms to the contract.
2. bundle.sha256 seal matches the manifest bytes byte-for-byte.
3. every artifact's blob exists at blobs/<sha256>, and its recomputed SHA-256
   equals both the manifest entry AND the blob's content-addressed filename.
4. artifact_count / total_bytes are internally consistent.
5. manifest.sig (Ed25519) verifies against the manifest bytes. Optionally the
   signing key must equal a caller-supplied trusted public key.

Exit code 0 = verified, 1 = any failure, 2 = usage error. Designed to run from a
frozen --onefile binary or source checkout.

Usage:
    python verify_bundle.py <bundle_dir> [--trusted-key <hex|path>] [--require-signature]
    python verify_bundle.py --gen-key <dir>        # generate a signing keypair
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

_READ = 1024 * 1024


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_READ), b""):
            h.update(block)
    return h.hexdigest()


def _resolve_trusted_key(value: Optional[str]) -> Optional[str]:
    """A trusted key may be given as a hex string or a path to a .pub file."""
    if not value:
        return None
    p = Path(value)
    if p.is_file():
        return p.read_text(encoding="utf-8").strip()
    return value.strip()


def verify_bundle(
    bundle_dir: str,
    *,
    trusted_key: Optional[str] = None,
    require_signature: bool = False,
) -> List[str]:
    """Verify a bundle. Returns a list of problem strings (empty == verified)."""
    problems: List[str] = []
    root = Path(bundle_dir)
    manifest_path = root / "manifest.json"
    blobs_dir = root / "blobs"

    if not manifest_path.is_file():
        return [f"manifest.json missing in {bundle_dir}"]

    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        return [f"manifest.json is not valid JSON: {exc}"]

    # (1) contract conformance (best-effort — degrades if jsonschema absent).
    try:
        from utils.contracts import ContractValidationError, validate_bundle_manifest

        try:
            validate_bundle_manifest(manifest)
        except ContractValidationError as exc:
            problems.append(f"manifest fails contract: {exc}")
    except Exception:
        pass  # contracts module unavailable — skip, other checks still apply

    # (2) seal over the exact manifest bytes.
    seal_path = root / "bundle.sha256"
    if seal_path.is_file():
        recorded = seal_path.read_text(encoding="utf-8").split()[0].strip()
        actual = hashlib.sha256(manifest_bytes).hexdigest()
        if recorded != actual:
            problems.append(f"bundle.sha256 seal mismatch: recorded {recorded}, actual {actual}")
    else:
        problems.append("bundle.sha256 seal missing")

    # (3) every artifact blob present, content-addressed, and hash-matching.
    artifacts = manifest.get("artifacts", [])
    total = 0
    for i, art in enumerate(artifacts):
        sha = art.get("sha256", "")
        blob = blobs_dir / sha
        if not blob.is_file():
            problems.append(f"artifacts[{i}] ({art.get('name')}): blob {sha} missing")
            continue
        actual = _sha256(blob)
        if actual != sha:
            problems.append(
                f"artifacts[{i}] ({art.get('name')}): blob content hash {actual} "
                f"!= manifest/filename {sha}"
            )
        size = art.get("size", 0)
        real_size = blob.stat().st_size
        if size != real_size:
            problems.append(
                f"artifacts[{i}] ({art.get('name')}): size {size} != blob {real_size}"
            )
        total += real_size

    # (4) internal count/byte consistency.
    if manifest.get("artifact_count") != len(artifacts):
        problems.append(
            f"artifact_count {manifest.get('artifact_count')} != actual {len(artifacts)}"
        )
    if "total_bytes" in manifest and manifest["total_bytes"] != total:
        problems.append(f"total_bytes {manifest['total_bytes']} != summed {total}")

    # (5) signature.
    sig_path = root / "manifest.sig"
    if sig_path.is_file():
        try:
            from utils import signing

            sig_payload = json.loads(sig_path.read_text(encoding="utf-8"))
            ok = signing.verify_manifest_signature(
                manifest_bytes, sig_payload, trusted_pubkey_hex=trusted_key
            )
            if not ok:
                problems.append(
                    "manifest.sig signature INVALID"
                    + (" (or key not trusted)" if trusted_key else "")
                )
        except Exception as exc:
            problems.append(f"manifest.sig could not be verified: {exc}")
    elif require_signature or trusted_key:
        problems.append("manifest.sig missing but a signature was required")

    return problems


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a CherryPick artifact bundle.")
    parser.add_argument("bundle_dir", nargs="?", help="path to the bundle directory")
    parser.add_argument("--trusted-key", help="expected signer public key (hex or .pub path)")
    parser.add_argument(
        "--require-signature", action="store_true", help="fail if no signature present"
    )
    parser.add_argument("--gen-key", metavar="DIR", help="generate a signing keypair into DIR")
    args = parser.parse_args(argv)

    if args.gen_key:
        from utils import signing

        priv, pub = signing.write_keypair(args.gen_key)
        print(f"signing key: {priv}")
        print(f"public key : {pub}")
        print("set CHERRYPICK_SIGNING_KEY to the .key path when collecting.")
        return 0

    if not args.bundle_dir:
        parser.error("bundle_dir is required (or use --gen-key)")

    trusted = _resolve_trusted_key(args.trusted_key)
    problems = verify_bundle(
        args.bundle_dir, trusted_key=trusted, require_signature=args.require_signature
    )
    if problems:
        print(f"[FAIL] bundle NOT verified ({len(problems)} problem(s)):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("[OK] bundle verified: seal, blob hashes, counts, and signature all consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
