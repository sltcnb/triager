"""
Discord collector for Triager.

Collects messaging/discord artifacts.
"""

import os
import logging

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime

logger = logging.getLogger(__name__)


class DiscordCollector(BaseCollector):
    """Collector for messaging/discord artifacts."""

    category = 'messaging_discord'

    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        self.result.start_time = self._get_time()
        self._ensure_output_dir()

        # Define artifact paths to collect
        artifact_paths = ['Users/*/AppData/Roaming/Discord/Cache', 'Users/*/AppData/Roaming/Discord/IndexedDB', 'Users/*/AppData/Roaming/Discord/Local Storage', 'Users/*/AppData/Roaming/Discord/logs']

        collected = 0
        for artifact_path in artifact_paths:
            # Handle wildcards in paths
            if '*' in artifact_path:
                # For wildcard paths, we need to enumerate
                parts = artifact_path.split('/')
                for i, part in enumerate(parts):
                    if '*' in part:
                        base_path = '/'.join(parts[:i]) if i > 0 else ''
                        pattern = part
                        remaining = '/'.join(parts[i+1:]) if i < len(parts) - 1 else ''

                        if base_path and self._path_exists(base_path):
                            entries = self._list_dir(base_path)
                            for entry in entries:
                                if pattern == '*' or (pattern.startswith('*') and entry.endswith(pattern[1:])) or (pattern.endswith('*') and entry.startswith(pattern[:-1])):
                                    full_path = f"{base_path}/{entry}"
                                    if remaining:
                                        full_path = f"{full_path}/{remaining}"
                                    if self._path_exists(full_path):
                                        filename = os.path.basename(full_path)
                                        if self._collect_file(full_path, '', filename):
                                            collected += 1
                        break
            else:
                # Direct path
                if self._path_exists(artifact_path):
                    filename = os.path.basename(artifact_path)
                    if self._collect_file(artifact_path, '', filename):
                        collected += 1

        self.result.files_collected = collected
        self.result.end_time = self._get_time()
        return self.result

