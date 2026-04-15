"""
Filesystem collector for ForensicHarvester.

Collects filesystem artifacts.
"""

import os
import logging
from typing import List

from collectors.base import BaseCollector, CollectionResult
from datetime import datetime
from utils.file_ops import ensure_directory

logger = logging.getLogger(__name__)


class FilesystemCollector(BaseCollector):
    """Collector for filesystem artifacts."""
    
    category = 'filesystem'
    
    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        """Collect filesystem artifacts."""
        self.result.start_time = self._get_time()
        self._ensure_output_dir()
        
        # NTFS metadata files
        ntfs_files = [
            ('$MFT', 'Windows/$MFT'),
            ('$MFTMirr', 'Windows/$MFTMirr'),
            ('$LogFile', 'Windows/$LogFile'),
            ('$Volume', 'Windows/$Volume'),
            ('$AttrDef', 'Windows/$AttrDef'),
            ('$Bitmap', 'Windows/$Bitmap'),
            ('$Boot', 'Windows/$Boot'),
        ]
        
        for dest_name, src_path in ntfs_files:
            if self._path_exists(src_path):
                self._collect_file(src_path, '', dest_name)
        
        # SDB files
        sdb_dir = 'Windows/AppPatch/Custom'
        if self._path_exists(sdb_dir):
            self._collect_dir_contents(sdb_dir, 'sdb_files', '*.sdb')
        
        # ADS inventory for exhaustive mode
        if self.level == 'exhaustive':
            self._enumerate_ads()
        
        self.result.end_time = self._get_time()
        return self.result
    
    def _enumerate_ads(self):
        """Enumerate Alternate Data Streams."""
        ads_csv = os.path.join(self.category_output, 'ads_inventory.csv')
        ensure_directory(self.category_output)
        
        with open(ads_csv, 'w') as f:
            f.write("file_path,stream_name,size\n")
        # ADS enumeration would require additional pytsk3 calls
        self.result.add_warning("ADS enumeration not fully implemented for image mode")

