"""Live-filesystem and mounted-volume sources (local OS path access)."""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional, Tuple

from sources.base import Source
from utils.file_ops import copy_file_with_metadata, extend_path

logger = logging.getLogger(__name__)

IS_WINDOWS = os.name == "nt"


class LiveFilesystemSource(Source):
    """Artifacts read from the local filesystem rooted at ``source_root``.

    On Windows, attempts to enable SeBackupPrivilege once so locked/ACL-protected
    system files (registry hives, event logs) can be copied; falls back to a
    robocopy backup-mode copy when a plain copy hits a sharing/permission error.
    """

    sequential = False

    def __init__(self, source_root: str):
        self.source_root = source_root or ("C:\\" if IS_WINDOWS else "/")
        self._backup_priv = False
        if IS_WINDOWS:
            self._enable_backup_privilege()

    def _enable_backup_privilege(self) -> None:
        try:
            from utils.privilege_utils import enable_backup_privileges

            backup_ok, _security_ok = enable_backup_privileges()
            self._backup_priv = bool(backup_ok)
            if self._backup_priv:
                logger.debug("SeBackupPrivilege enabled")
        except Exception as exc:
            logger.debug("could not enable backup privileges: %s", exc)

    def expand(self, path: str) -> str:
        if os.path.isabs(path):
            return extend_path(path)
        return extend_path(os.path.join(self.source_root, path))

    def exists(self, path: str) -> bool:
        return os.path.exists(self.expand(path))

    def is_file(self, path: str) -> bool:
        p = self.expand(path)
        return os.path.isfile(p) if os.path.exists(p) else False

    def list_dir(self, path: str) -> List[str]:
        p = self.expand(path)
        if os.path.isdir(p):
            try:
                return os.listdir(p)
            except OSError as exc:
                logger.debug("list_dir failed %s: %s", p, exc)
        return []

    def file_size(self, path: str) -> int:
        try:
            return os.path.getsize(self.expand(path))
        except OSError:
            return 0

    def extract(self, src_path: str, dest_path: str) -> Tuple[bool, Optional[str]]:
        src = self.expand(src_path)
        if not os.path.exists(src):
            return False, "Source file not found"
        ok, err = copy_file_with_metadata(src, dest_path)
        if ok:
            return True, None
        # Locked/ACL-protected file on Windows: retry via robocopy backup mode.
        if IS_WINDOWS:
            if self._robocopy_backup(src, dest_path):
                return True, None
        return False, err

    def _robocopy_backup(self, src: str, dest: str) -> bool:
        """Copy a locked file using robocopy /B (backup mode, needs SeBackupPrivilege)."""
        try:
            src_dir, src_name = os.path.split(src)
            dst_dir, dst_name = os.path.split(dest)
            os.makedirs(dst_dir, exist_ok=True)
            r = subprocess.run(
                ["robocopy", src_dir, dst_dir, src_name, "/B", "/R:1", "/W:1", "/NP", "/NJH", "/NJS"],
                capture_output=True,
                timeout=120,
            )
            # robocopy exit codes < 8 indicate success (files copied / nothing to do).
            if r.returncode < 8 and os.path.exists(os.path.join(dst_dir, src_name)):
                if src_name != dst_name:
                    os.replace(os.path.join(dst_dir, src_name), dest)
                return True
        except Exception as exc:
            logger.debug("robocopy backup failed %s: %s", src, exc)
        return False

    def roots(self) -> List[str]:
        if IS_WINDOWS:
            import string

            found = []
            for letter in string.ascii_uppercase:
                d = f"{letter}:\\"
                if os.path.exists(d):
                    found.append(d)
            return found or [self.source_root]
        return [self.source_root]


class MountedVolumeSource(LiveFilesystemSource):
    """A mounted volume (dead-box). Identical to live access, different root.

    Use for ``--path /mnt/windows`` and as the backing for a device that has been
    unlocked+mounted by :class:`~sources.rawdevice.RawDeviceSource`.
    """

    sequential = False

    def __init__(self, mount_path: str):
        # Do not attempt to enable host backup privileges for a foreign mount.
        self.source_root = mount_path
        self._backup_priv = False

    def roots(self) -> List[str]:
        return [self.source_root]
