"""
Pluggable ArtifactCollector interface (ported from Talon).

A stdlib-only lifecycle contract:

    start()      → prepare staging, record session metadata
    collect()    → gather the declared artifact categories
    finalize()   → seal the session and return a contract-conformant result

The produced manifest conforms to FH's vendored
``contracts/bundle_manifest.schema.json`` (bundle layout:
``bundle/ { manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256 }``).

NOTE ON NAMING: Talon called the session dataclass ``CollectionResult``. FH
already has an unrelated ``collectors.base.CollectionResult`` (per-category
statistics). To avoid the collision flagged in the plan, the session-level type
is named :class:`SessionResult` here. The two are mapped at the orchestrator
boundary, never unified.
"""

from __future__ import annotations

import abc
import datetime
import hashlib
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

CHUNK_READ = 1024 * 1024  # 1 MiB read window for hashing

#: Acquisition tool version, surfaced in the manifest chain-of-custody block.
#: Keep in sync with brick.yaml ``version`` and triager.py ``--version``.
TOOL_VERSION = "1.2.0"
TOOL_NAME = "CherryPick"

_OS_ENUM = {"windows": "windows", "linux": "linux", "darwin": "macos"}


def host_os() -> str:
    """Return the manifest-conformant OS string for the running host."""
    return _OS_ENUM.get(platform.system().lower(), "unknown")


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of a file (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK_READ), b""):
            h.update(block)
    return h.hexdigest()


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ArtifactRef:
    """One collected artifact, as it appears in the manifest ``artifacts[]``."""

    name: str  # path inside the bundle (e.g. blobs/<sha256> or arcname)
    sha256: str
    size: int
    category: str
    collected_at: Optional[str] = None  # UTC time the source was collected

    def to_manifest(self) -> dict:
        m = {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "category": self.category,
        }
        if self.collected_at:
            m["collected_at"] = self.collected_at
        return m


@dataclass
class SessionResult:
    """Outcome of a full start/collect/finalize cycle (session-level)."""

    session_id: str
    hostname: str
    os: str
    started_at: str
    finished_at: Optional[str] = None
    artifacts: List[ArtifactRef] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    #: Structured record of artifacts that were attempted but NOT obtained
    #: (failed/skipped). Preserving gaps makes absences provable rather than
    #: silently dropped — critical for a defensible acquisition.
    gaps: List[dict] = field(default_factory=list)
    #: Chain-of-custody metadata (operator, tool/collector versions, host id,
    #: argv, ...). Populated by the orchestrator at finalize().
    chain_of_custody: Optional[dict] = None

    @property
    def total_bytes(self) -> int:
        return sum(a.size for a in self.artifacts)

    def to_manifest(self) -> dict:
        """Render the contract-conformant manifest.json payload."""
        manifest = {
            "session_id": self.session_id,
            "hostname": self.hostname,
            "os": self.os,
            "started_at": self.started_at,
            "artifacts": [a.to_manifest() for a in self.artifacts],
            "artifact_count": len(self.artifacts),
            "total_bytes": self.total_bytes,
            "errors": list(self.errors),
        }
        if self.finished_at:
            manifest["finished_at"] = self.finished_at
        if self.gaps:
            manifest["gaps"] = list(self.gaps)
        if self.chain_of_custody:
            manifest["chain_of_custody"] = dict(self.chain_of_custody)
        return manifest


class ArtifactCollector(abc.ABC):
    """Abstract base for a pluggable artifact collector.

    Lifecycle (the orchestrator calls these in order)::

        c = SomeCollector(...)
        c.start()
        c.collect()
        result = c.finalize()
    """

    def __init__(
        self, session_id: str, *, hostname: Optional[str] = None, os_name: Optional[str] = None
    ) -> None:
        self.session_id = session_id
        self.hostname = hostname or socket.gethostname()
        self.os = os_name or host_os()
        self.result = SessionResult(
            session_id=self.session_id,
            hostname=self.hostname,
            os=self.os,
            started_at=now_iso(),
        )

    @abc.abstractmethod
    def categories(self) -> Set[str]:
        """Artifact categories this collector is configured to produce."""

    @classmethod
    def supported_categories(cls) -> Set[str]:
        return set()

    @abc.abstractmethod
    def start(self) -> None:
        """Prepare for collection (staging dirs, privileges, mounts)."""

    @abc.abstractmethod
    def collect(self) -> None:
        """Run collection for the declared categories."""

    @abc.abstractmethod
    def finalize(self) -> SessionResult:
        """Seal the session and return the :class:`SessionResult`."""
