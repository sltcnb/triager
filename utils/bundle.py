"""
Content-addressed artifact bundle writer.

Produces the Talon/Citadel bundle layout from a completed collection::

    bundle/
      manifest.json        # conforms to contracts/bundle_manifest.schema.json
      events.jsonl         # one forensic_event per artifact (forensic_event.schema.json)
      blobs/<sha256>       # content-addressed artifact payloads (deduplicated)
      bundle.sha256        # SHA-256 over manifest.json (seals the manifest)

The writer is fed the staged collection output directory (where the per-category
collectors copied their files) and a
:class:`~collectors.artifact_collector.SessionResult`. Blobs are addressed by
content hash, so identical files collected under multiple categories are stored
once.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
from pathlib import Path

from collectors.artifact_collector import SessionResult, now_iso
from utils.contracts import validate_bundle_manifest

logger = logging.getLogger(__name__)

_READ = 1024 * 1024


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_READ), b""):
            h.update(block)
    return h.hexdigest()


class BundleWriter:
    """Write a content-addressed artifact bundle from staged collection output."""

    def __init__(self, staged_root: str, bundle_dir: str, *, signing_key: bytes | None = None):
        self.staged_root = Path(staged_root)
        self.bundle_dir = Path(bundle_dir)
        self.blobs_dir = self.bundle_dir / "blobs"
        # Explicit key wins; otherwise resolve from the environment. None → the
        # bundle is written UNSIGNED and a loud warning is emitted.
        self.signing_key = signing_key
        if self.signing_key is None:
            try:
                from utils import signing

                self.signing_key = signing.load_signing_key()
            except Exception as exc:  # key misconfig must not crash collection
                logger.error("bundle: signing key could not be loaded: %s", exc)
                self.signing_key = None

    def write(self, result: SessionResult, *, validate: bool = True) -> Path:
        """Materialize the bundle. Returns the bundle directory path.

        Raises :class:`~utils.contracts.ContractValidationError` (when
        ``validate``) if the manifest does not conform — fail closed before
        sealing.
        """
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

        events_path = self.bundle_dir / "events.jsonl"
        with open(events_path, "w", encoding="utf-8") as events:
            for art in result.artifacts:
                blob = self.blobs_dir / art.sha256
                if not blob.exists():  # content-addressed dedup
                    src = self.staged_root / art.name
                    try:
                        shutil.copy2(src, blob)
                    except OSError as exc:
                        logger.warning("bundle: could not copy %s: %s", src, exc)
                        result.errors.append(f"blob copy failed {art.name}: {exc}")
                        continue
                events.write(json.dumps(self._event(art)) + "\n")

        manifest = result.to_manifest()
        if validate:
            validate_bundle_manifest(manifest)  # raises on non-conformance

        manifest_path = self.bundle_dir / "manifest.json"
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)

        # bundle.sha256 seals the manifest against corruption (recomputable).
        seal = hashlib.sha256(manifest_bytes).hexdigest()
        (self.bundle_dir / "bundle.sha256").write_text(
            f"{seal}  manifest.json\n", encoding="utf-8"
        )

        # manifest.sig is the tamper-EVIDENCE: an Ed25519 signature over the exact
        # manifest bytes. Because every blob hash lives in the manifest, a valid
        # signature transitively attests the whole bundle.
        self._sign_manifest(manifest_bytes)

        logger.info("bundle written: %s (%d artifacts)", self.bundle_dir, len(result.artifacts))
        return self.bundle_dir

    def _sign_manifest(self, manifest_bytes: bytes) -> None:
        from utils import signing

        if not self.signing_key:
            logger.warning(
                "bundle: NO signing key configured — manifest is UNSIGNED and not "
                "tamper-evident. Set CHERRYPICK_SIGNING_KEY for a defensible bundle."
            )
            return
        try:
            sig_payload = signing.sign_manifest(manifest_bytes, self.signing_key)
        except Exception as exc:
            logger.error("bundle: manifest signing failed: %s", exc)
            return
        (self.bundle_dir / signing.SIG_FILENAME).write_text(
            json.dumps(sig_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        logger.info("bundle: manifest signed (ed25519)")

    def _event(self, art) -> dict:
        """Render a forensic_event.schema.json-conformant record for an artifact."""
        return {
            "timestamp": getattr(art, "collected_at", None) or now_iso(),
            "message": f"collected {art.name} ({art.category})",
            "artifact_type": art.category,
            "timestamp_desc": "collection",
            "os": self._os_hint(),
            "source_path": art.name,
            "parser": "triager",
            "raw": art.to_manifest(),
        }

    def _os_hint(self) -> str:
        # events os enum differs slightly from manifest; keep it simple/valid.
        return "cross"
