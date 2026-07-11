"""
EventLogs collector for Triager.

Collects eventlogs artifacts.
"""

import os
import logging

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime

logger = logging.getLogger(__name__)


class EventLogsCollector(BaseCollector):
    """Collector for eventlogs artifacts."""

    category = 'eventlogs'

    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        """Collect Windows event logs."""
        self.result.start_time = self._get_time()
        self._ensure_output_dir()

        logs_dir = 'Windows/System32/winevt/Logs'

        if not self._path_exists(logs_dir):
            self.result.add_warning(f"Event logs directory not found: {logs_dir}")
            self.result.end_time = self._get_time()
            return self.result

        # Critical logs for small level
        critical_logs = [
            'Security.evtx', 'System.evtx', 'Application.evtx',
            'Microsoft-Windows-PowerShell%4Operational.evtx',
            'Microsoft-Windows-Sysmon%4Operational.evtx',
            'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx',
            'Microsoft-Windows-Windows Defender%4Operational.evtx',
        ]

        if self.level == 'small':
            logs_to_collect = critical_logs
        else:
            # Collect all .evtx files
            logs_to_collect = None

        entries = self._list_dir(logs_dir) if self.image else os.listdir(self._expand_path(logs_dir))

        for entry_name in entries:
            if not entry_name.endswith('.evtx'):
                continue

            if logs_to_collect and entry_name not in logs_to_collect:
                # Check for pattern matches
                should_collect = False
                for pattern in logs_to_collect:
                    if '*' in pattern and entry_name.startswith(pattern.replace('*', '')):
                        should_collect = True
                        break
                if not should_collect:
                    continue

            self._collect_file(f"{logs_dir}/{entry_name}", '', entry_name)

        self.result.end_time = self._get_time()
        return self.result

