"""
Registry collector for Triager.

Collects registry artifacts.
"""

import os
import logging

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime

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

        # Offline enrichment: parse the copied hives into an autoruns/persistence
        # JSON (dead-box friendly). Degrades to a warning if python-registry is
        # unavailable or no hives were copied.
        self._export_autoruns()

        self.result.end_time = self._get_time()
        return self.result

    def _export_autoruns(self):
        try:
            from utils.registry_utils import export_autoruns_to_json, REGISTRY_LIB_AVAILABLE
        except Exception as e:
            self.result.add_warning(f"registry_utils unavailable: {e}")
            return
        if not REGISTRY_LIB_AVAILABLE:
            self.result.add_warning("python-registry not installed — skipping autoruns export")
            return
        system_hive = os.path.join(self.category_output, 'SYSTEM')
        if not os.path.exists(system_hive):
            return
        out_json = os.path.join(self.category_output, 'autoruns.json')
        try:
            export_autoruns_to_json(self.category_output, out_json)
            if os.path.exists(out_json):
                self._register_derived_output(out_json)
        except Exception as e:
            self.result.add_warning(f"autoruns export failed: {e}")

