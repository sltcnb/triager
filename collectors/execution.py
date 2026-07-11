"""
Execution collector for Triager.

Collects execution artifacts.
"""

import logging

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime

logger = logging.getLogger(__name__)


class ExecutionCollector(BaseCollector):
    """Collector for execution artifacts."""

    category = 'execution'

    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        """Collect execution artifacts."""
        self.result.start_time = self._get_time()

        # Prefetch
        prefetch_dir = 'Windows/Prefetch'
        if self._path_exists(prefetch_dir):
            self._ensure_output_dir('prefetch')
            self._collect_dir_contents(prefetch_dir, 'prefetch', '*.pf')

        # Superfetch
        superfetch_dir = 'Windows/Prefetch'
        if self._path_exists(superfetch_dir):
            self._ensure_output_dir('superfetch')
            for pattern in ['AgApp*.db', 'AgGl*.db']:
                self._collect_dir_contents(superfetch_dir, 'superfetch', pattern)

        # SRUM
        srum_db = 'Windows/System32/sru/SRUDB.dat'
        if self._path_exists(srum_db):
            self._ensure_output_dir('srum')
            self._collect_file(srum_db, 'srum', 'SRUDB.dat')

        # Amcache
        amcache = 'Windows/AppCompat/Programs/Amcache.hve'
        if self._path_exists(amcache):
            self._ensure_output_dir('amcache')
            self._collect_file(amcache, 'amcache', 'Amcache.hve')

        # Timeline/ActivitiesCache
        # Users/*/AppData/Local/Microsoft/Windows/ActivitiesCache.db
        # Would need glob support for the wildcard user directory.

        # PCA logs
        pca_dir = 'Windows/PCA'
        if self._path_exists(pca_dir):
            self._ensure_output_dir('pca')
            self._collect_dir_contents(pca_dir, 'pca')

        self.result.end_time = self._get_time()
        return self.result

