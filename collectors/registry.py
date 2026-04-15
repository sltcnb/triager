"""
Registry collector for ForensicHarvester.

Collects registry artifacts.
"""

import os
import logging
from typing import List

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime
from utils.file_ops import ensure_directory

logger = logging.getLogger(__name__)


class RegistryCollector(BaseCollector):
    """Collector for registry artifacts."""
    
    category = 'registry'
    
    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        """Collect registry hives."""
        self.result.start_time = self._get_time()
        self._ensure_output_dir()
        
        # System registry hives
        system_hives = {
            'SYSTEM': 'Windows/System32/config/SYSTEM',
            'SOFTWARE': 'Windows/System32/config/SOFTWARE',
            'SAM': 'Windows/System32/config/SAM',
            'SECURITY': 'Windows/System32/config/SECURITY',
            'DEFAULT': 'Windows/System32/config/DEFAULT',
            'COMPONENTS': 'Windows/System32/config/COMPONENTS',
            'BCD': 'Windows/System32/config/BCD',
            'AMCACHE': 'Windows/AppCompat/Programs/Amcache.hve',
        }
        
        for hive_name, hive_path in system_hives.items():
            self._collect_file(hive_path, '', hive_name)
            # Also collect log files
            for log_ext in ['.LOG1', '.LOG2']:
                log_path = hive_path + log_ext
                if self._path_exists(log_path):
                    self._collect_file(log_path, '', hive_name + log_ext)
        
        # User registry hives
        users_dir = 'Users'
        if self._path_exists(users_dir):
            users = self._list_dir(users_dir)
            for username in users:
                if username in ['Default', 'Public', 'All Users']:
                    continue
                user_path = f"{users_dir}/{username}"
                if self._path_exists(f"{user_path}/NTUSER.DAT"):
                    self._collect_file(f"{user_path}/NTUSER.DAT", f'users/{username}', 'NTUSER.DAT')
                    for log_ext in ['.LOG1', '.LOG2']:
                        log_path = f"{user_path}/NTUSER.DAT{log_ext}"
                        if self._path_exists(log_path):
                            self._collect_file(log_path, f'users/{username}', f'NTUSER.DAT{log_ext}')
                if self._path_exists(f"{user_path}/UsrClass.dat"):
                    self._collect_file(f"{user_path}/UsrClass.dat", f'users/{username}', 'UsrClass.dat')
        
        self.result.end_time = self._get_time()
        return self.result

