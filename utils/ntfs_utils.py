"""
NTFS utilities for Triager.

This module provides NTFS-specific functionality for accessing metadata files,
enumerating ADS, and parsing NTFS structures.
"""

import os
import ctypes
import logging
import struct
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from utils.file_ops import extend_path
from utils.constants import NTFS_METADATA_FILES, ADS_ZONE_IDENTIFIER

logger = logging.getLogger(__name__)

# Try to import pytsk3 for raw NTFS access
try:
    import pytsk3
    PYTSK_AVAILABLE = True
except ImportError:
    PYTSK_AVAILABLE = False
    logger.debug("pytsk3 not available, raw NTFS access disabled")


@dataclass
class ADSInfo:
    """Information about an Alternate Data Stream."""
    file_path: str
    stream_name: str
    size: int
    content_hash: Optional[str] = None


@dataclass
class MFTEntry:
    """Information about an MFT entry."""
    record_number: int
    sequence_number: int
    file_name: str
    file_size: int
    flags: int
    is_deleted: bool
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    mft_modified: Optional[str] = None


class NTFSAccess:
    """Access to NTFS filesystem structures."""

    def __init__(self, drive_letter: str = 'C:'):
        """
        Initialize NTFS access.
        
        Args:
            drive_letter: Drive letter to access.
        """
        self.drive_letter = drive_letter
        self.device_path = f"\\\\.\\{drive_letter}"
        self.image = None

        if PYTSK_AVAILABLE:
            try:
                self.image = pytsk3.Image(self.device_path)
            except Exception as e:
                logger.warning(f"Failed to open {self.device_path}: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def collect_metadata_files(
        self,
        output_dir: str,
    ) -> List[Dict]:
        """
        Collect NTFS metadata files.
        
        Args:
            output_dir: Directory to save metadata files.
            
        Returns:
            List of collection results.
        """
        results = []

        if PYTSK_AVAILABLE and self.image:
            try:
                fs_info = self.image.open()

                for metadata_file in NTFS_METADATA_FILES:
                    try:
                        # Try to open the metadata file
                        file_obj = fs_info.open(metadata_file)

                        # Create output path
                        safe_name = metadata_file.replace('$', '').replace(':', '_')
                        output_path = os.path.join(output_dir, safe_name)

                        # Read and write
                        with open(output_path, 'wb') as f:
                            while True:
                                data = file_obj.read(65536)
                                if not data:
                                    break
                                f.write(data)

                        results.append({
                            'file': metadata_file,
                            'output': output_path,
                            'success': True,
                            'error': None,
                        })

                    except Exception as e:
                        results.append({
                            'file': metadata_file,
                            'output': None,
                            'success': False,
                            'error': str(e),
                        })

            except Exception as e:
                logger.error(f"Failed to access filesystem: {e}")
        else:
            logger.warning("pytsk3 not available, cannot collect NTFS metadata")

        return results

    def enumerate_ads(
        self,
        file_path: str,
    ) -> List[ADSInfo]:
        """
        Enumerate Alternate Data Streams for a file.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            List of ADSInfo objects.
        """
        ads_list = []

        try:
            # Use Windows API for ADS enumeration
            handle = ctypes.windll.kernel32.CreateFileW(
                extend_path(file_path),
                0x00080000,  # GENERIC_READ
                0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                None,
                3,  # OPEN_EXISTING
                0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                None,
            )

            if handle == -1 or handle == 0xFFFFFFFFFFFFFFFF:
                return ads_list

            try:
                # Get file information
                buffer = ctypes.create_unicode_buffer(32768)
                result = ctypes.windll.kernel32.GetFileInformationByHandleEx(
                    handle,
                    22,  # FileStreamInfo
                    buffer,
                    len(buffer),
                )

                if result:
                    # Parse the stream information
                    # (Simplified - full parsing would require more complex structure)
                    pass

            finally:
                ctypes.windll.kernel32.CloseHandle(handle)

        except Exception as e:
            logger.debug(f"Error enumerating ADS for {file_path}: {e}")

        # Fallback: Try to find Zone.Identifier and common ADS
        common_ads = [
            ADS_ZONE_IDENTIFIER,
            ':SummaryInformation',
            ':Ole10Native',
        ]

        for ads_name in common_ads:
            ads_path = f"{file_path}{ads_name}"
            if os.path.exists(extend_path(ads_path)):
                try:
                    size = os.path.getsize(extend_path(ads_path))
                    ads_list.append(ADSInfo(
                        file_path=file_path,
                        stream_name=ads_name,
                        size=size,
                    ))
                except Exception:
                    pass

        return ads_list

    def get_usn_journal(
        self,
        output_path: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Extract the USN Journal ($UsnJrnl:$J).
        
        Args:
            output_path: Path to save the journal.
            
        Returns:
            Tuple of (success, error_message).
        """
        if not PYTSK_AVAILABLE or not self.image:
            return False, "pytsk3 not available"

        try:
            fs_info = self.image.open()

            # Open $Extend/$UsnJrnl
            usn_path = '$Extend/$UsnJrnl:$J'
            file_obj = fs_info.open(usn_path)

            with open(extend_path(output_path), 'wb') as f:
                while True:
                    data = file_obj.read(65536)
                    if not data:
                        break
                    f.write(data)

            return True, None

        except Exception as e:
            logger.error(f"Failed to extract USN Journal: {e}")
            return False, str(e)

    def parse_mft_entries(
        self,
        mft_path: str,
        max_entries: int = 100000,
    ) -> List[MFTEntry]:
        """
        Parse MFT entries from an MFT file.
        
        Args:
            mft_path: Path to the MFT file.
            max_entries: Maximum number of entries to parse.
            
        Returns:
            List of MFTEntry objects.
        """
        entries = []

        try:
            with open(extend_path(mft_path), 'rb') as f:
                for i in range(max_entries):
                    # Read MFT record header (1024 bytes per record typically)
                    record_data = f.read(1024)
                    if len(record_data) < 1024:
                        break

                    # Check for FILE signature
                    if record_data[:4] != b'FILE':
                        continue

                    # Parse basic fields
                    try:
                        # Sequence number at offset 4
                        seq_num = struct.unpack('<H', record_data[4:6])[0]

                        # Flags at offset 22
                        flags = struct.unpack('<H', record_data[22:24])[0]

                        # Check if deleted (flag bit 0)
                        is_deleted = bool(flags & 0x0001)

                        # Get record number
                        record_num = i

                        # Try to extract filename (simplified)
                        file_name = f"MFT_RECORD_{record_num}"

                        entry = MFTEntry(
                            record_number=record_num,
                            sequence_number=seq_num,
                            file_name=file_name,
                            file_size=0,
                            flags=flags,
                            is_deleted=is_deleted,
                        )

                        entries.append(entry)

                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"Failed to parse MFT: {e}")

        return entries

    def collect_ads_inventory(
        self,
        root_path: str,
        output_csv: str,
    ) -> List[ADSInfo]:
        """
        Collect an inventory of all ADS in a directory tree.
        
        Args:
            root_path: Root directory to search.
            output_csv: Path for output CSV file.
            
        Returns:
            List of all ADS found.
        """
        all_ads = []

        try:
            for dirpath, dirnames, filenames in os.walk(extend_path(root_path)):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    ads_list = self.enumerate_ads(file_path)
                    all_ads.extend(ads_list)

            # Write CSV
            with open(output_csv, 'w', encoding='utf-8') as f:
                f.write("file_path,stream_name,size,content_hash\n")
                for ads in all_ads:
                    f.write(f'"{ads.file_path}","{ads.stream_name}",{ads.size},"{ads.content_hash or ""}"\n')

        except Exception as e:
            logger.error(f"Error collecting ADS inventory: {e}")

        return all_ads


def collect_ntfs_artifacts(
    drive_letter: str,
    output_dir: str,
    level: str,
) -> Dict:
    """
    Collect NTFS-specific artifacts.
    
    Args:
        drive_letter: Drive to collect from.
        output_dir: Output directory.
        level: Collection level.
        
    Returns:
        Dictionary with collection results.
    """
    results = {
        'metadata_files': [],
        'usn_journal': None,
        'ads_inventory': [],
        'mft_entries': [],
    }

    with NTFSAccess(drive_letter) as ntfs:
        # Collect metadata files
        metadata_dir = os.path.join(output_dir, 'filesystem')
        os.makedirs(metadata_dir, exist_ok=True)
        results['metadata_files'] = ntfs.collect_metadata_files(metadata_dir)

        # Collect USN Journal
        if level in ['complete', 'exhaustive']:
            usn_path = os.path.join(metadata_dir, '$UsnJrnl_$J')
            success, error = ntfs.get_usn_journal(usn_path)
            results['usn_journal'] = {
                'success': success,
                'error': error,
                'path': usn_path if success else None,
            }

        # Collect ADS inventory
        if level == 'exhaustive':
            ads_csv = os.path.join(metadata_dir, 'ads_inventory.csv')
            results['ads_inventory'] = ntfs.collect_ads_inventory(
                f"{drive_letter}\\",
                ads_csv,
            )

    return results
