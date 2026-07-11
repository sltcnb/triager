"""
Base collector module for Triager.

This module defines the base class and interfaces for all artifact collectors.
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from utils.file_ops import ensure_directory
from utils.hash_utils import hash_file_streaming
from utils.manifest import CollectionManifest

logger = logging.getLogger(__name__)


@dataclass
class CollectionResult:
    """Result of a collection operation."""
    category: str
    files_collected: int = 0
    files_failed: int = 0
    files_skipped: int = 0
    total_bytes: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration_seconds(self) -> float:
        """Get collection duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def success_rate(self) -> float:
        """Get success rate percentage."""
        total = self.files_collected + self.files_failed
        if total == 0:
            return 100.0
        return (self.files_collected / total) * 100

    def add_error(self, error: str):
        """Add an error message."""
        self.errors.append(error)
        logger.error(error)

    def add_warning(self, warning: str):
        """Add a warning message."""
        self.warnings.append(warning)
        logger.warning(warning)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'category': self.category,
            'files_collected': self.files_collected,
            'files_failed': self.files_failed,
            'files_skipped': self.files_skipped,
            'total_bytes': self.total_bytes,
            'total_mb': self.total_bytes / (1024 * 1024),
            'errors': self.errors,
            'warnings': self.warnings,
            'details': self.details,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'success_rate': self.success_rate,
        }


class BaseCollector(ABC):
    """
    Base class for all artifact collectors.
    
    Each collector must implement the collect() method and define
    its category name.
    """

    # Category name - must be overridden by subclasses
    category: str = 'base'

    # Default paths to collect - can be overridden
    default_paths: List[str] = []

    # File patterns to match - can be overridden
    file_patterns: List[str] = []

    def __init__(
        self,
        config: Dict,
        source_root: str,
        output_root: str,
        level: str,
        manifest: CollectionManifest,
        image: Any = None,
    ):
        """
        Initialize the collector.
        
        Args:
            config: Configuration dictionary.
            source_root: Root path of source (live system or mounted image).
            output_root: Root output directory.
            level: Collection level (small, complete, exhaustive).
            manifest: Collection manifest for tracking.
        """
        self.config = config
        self.source_root = source_root
        self.output_root = output_root
        self.level = level
        self.manifest = manifest
        self.image = image  # DiskImage object for raw image access (legacy accessor)
        self.result = CollectionResult(category=self.category)

        # Unified source abstraction. A caller may inject a prepared Source via
        # config['_source']; otherwise one is derived from image/source_root so
        # the 51 existing collectors work unchanged.
        self.source = config.get('_source') if isinstance(config, dict) else None
        if self.source is None:
            from sources import build_source
            self.source = build_source(source_root, image=image)

        # Category-specific output directory
        self.category_output = self._get_category_output_dir()

    @classmethod
    def supported_categories(cls) -> set:
        """Category keys this collector class can produce.

        Defaults to ``{cls.category}``; collectors that expose more than one
        key may override. Used by the registry to build the key→class map and
        validate against ``capabilities.yaml``.
        """
        return {cls.category}

    def _get_category_output_dir(self) -> str:
        """
        Get the output directory for this collector's category.
        
        Returns:
            Output directory path.
        """
        # Map category to output directory
        category_map = {
            'registry': 'registry',
            'eventlogs': 'eventlogs',
            'filesystem': 'filesystem',
            'execution': 'execution',
            'persistence': 'persistence',
            'network': 'network',
            'usb_devices': 'usb_devices',
            'browser_chrome': 'browser/chrome',
            'browser_firefox': 'browser/firefox',
            'browser_edge': 'browser/edge',
            'browser_ie': 'browser/ie',
            'email_outlook': 'email/outlook',
            'email_thunderbird': 'email/thunderbird',
            'email_other': 'email/other',
            'teams': 'messaging/teams',
            'slack': 'messaging/slack',
            'discord': 'messaging/discord',
            'signal': 'messaging/signal',
            'whatsapp': 'messaging/whatsapp',
            'telegram': 'messaging/telegram',
            'cloud_onedrive': 'cloud/onedrive',
            'cloud_google_drive': 'cloud/google_drive',
            'cloud_dropbox': 'cloud/dropbox',
            'cloud_other': 'cloud/other',
            'remote_access': 'remote_access',
            'rdp': 'rdp',
            'ssh_ftp': 'ssh_ftp',
            'credentials': 'credentials',
            'office': 'office',
            'antivirus': 'antivirus',
            'wer_crashes': 'wer_crashes',
            'iis_web': 'iis_web',
            'active_directory': 'active_directory',
            'database_clients': 'database_clients',
            'dev_tools': 'dev_tools',
            'password_managers': 'password_managers',
            'vpn': 'vpn',
            'gaming': 'gaming',
            'printing': 'printing',
            'encryption': 'encryption',
            'boot_uefi': 'boot_uefi',
            'etw_diagnostics': 'etw_diagnostics',
            'windows_apps': 'windows_apps',
            'wsl': 'wsl',
            'virtualization': 'virtualization',
            'recovery': 'recovery',
            'logs': 'logs',
            'memory': 'memory',
            'hashing': 'hashing',
            'file_listing': 'file_listing',
            'yara_scanner': 'yara',
        }

        subdir = category_map.get(self.category, self.category)
        return os.path.join(self.output_root, subdir)

    def _expand_path(self, path: str) -> str:
        """
        Expand a path relative to source root.
        
        Args:
            path: Path to expand.
            
        Returns:
            Expanded absolute path.
        """
        return self.source.expand(path)

    def _ensure_output_dir(self, subpath: str = '') -> str:
        """
        Ensure output directory exists.
        
        Args:
            subpath: Optional subpath within category output.
            
        Returns:
            Output directory path.
        """
        if subpath:
            output_dir = os.path.join(self.category_output, subpath)
        else:
            output_dir = self.category_output

        ensure_directory(output_dir)
        return output_dir

    def _collect_file(
        self,
        source_path: str,
        dest_subpath: str,
        dest_filename: str,
        hash_file: bool = True,
    ) -> bool:
        """
        Collect a single file.
        
        Args:
            source_path: Source file path.
            dest_subpath: Subpath within category output.
            dest_filename: Destination filename.
            hash_file: Whether to hash the file.
            
        Returns:
            True if successful.
        """
        try:
            if not self._path_exists(source_path):
                self.result.files_skipped += 1
                self.manifest.add_entry(
                    source_path=source_path,
                    dest_path=os.path.join(dest_subpath, dest_filename),
                    status='skipped',
                    category=self.category,
                    error='File does not exist',
                )
                return False

            if not self._is_file(source_path):
                self.result.files_skipped += 1
                self.manifest.add_entry(
                    source_path=source_path,
                    dest_path=os.path.join(dest_subpath, dest_filename),
                    status='skipped',
                    category=self.category,
                    error='Not a regular file',
                )
                return False

            # Check file size limit
            max_size = self.config.get('max_file_size_mb', 0)
            if max_size > 0:
                file_size = self._get_file_size(source_path)
                if file_size > max_size * 1024 * 1024:
                    self.result.files_skipped += 1
                    self.manifest.add_entry(
                        source_path=source_path,
                        dest_path=os.path.join(dest_subpath, dest_filename),
                        status='skipped',
                        category=self.category,
                        error=f'File exceeds size limit ({file_size} > {max_size}MB)',
                    )
                    return False

            # Ensure destination directory exists
            output_dir = self._ensure_output_dir(dest_subpath)
            dest_path = os.path.join(output_dir, dest_filename)

            # Extract/copy the file
            success, error = self._extract_file(source_path, dest_path)

            if not success:
                self.result.files_failed += 1
                self.manifest.add_entry(
                    source_path=source_path,
                    dest_path=os.path.join(dest_subpath, dest_filename),
                    status='failed',
                    category=self.category,
                    error=error,
                )
                self.result.add_error(f"Failed to collect {source_path}: {error}")
                return False

            # Get file metadata
            try:
                stat_info = os.stat(dest_path)
                file_size = stat_info.st_size
                created = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                modified = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                accessed = datetime.fromtimestamp(stat_info.st_atime).isoformat()
            except Exception:
                file_size = 0
                created = None
                modified = None
                accessed = None

            # Hash the file if requested
            md5 = None
            sha256 = None

            if hash_file and self.config.get('hash_collected', True):
                try:
                    hash_result = hash_file_streaming(dest_path)
                    md5 = hash_result.md5
                    sha256 = hash_result.sha256
                except Exception as e:
                    self.result.add_warning(f"Failed to hash {dest_filename}: {e}")

            # Record the path relative to output_root so downstream consumers
            # (bundle writer, ZIP) can locate the staged blob deterministically.
            try:
                rel_dest = os.path.relpath(dest_path, self.output_root)
            except ValueError:
                rel_dest = os.path.join(dest_subpath, dest_filename)

            # Add to manifest
            self.manifest.add_entry(
                source_path=source_path,
                dest_path=rel_dest,
                status='success',
                category=self.category,
                md5=md5,
                sha256=sha256,
                size_bytes=file_size,
                source_created=created,
                source_modified=modified,
                source_accessed=accessed,
            )

            self.result.files_collected += 1
            self.result.total_bytes += file_size

            return True

        except Exception as e:
            self.result.files_failed += 1
            self.manifest.add_entry(
                source_path=source_path,
                dest_path=os.path.join(dest_subpath, dest_filename),
                status='failed',
                category=self.category,
                error=str(e),
            )
            self.result.add_error(f"Exception collecting {source_path}: {e}")
            return False

    def _collect_files_by_pattern(
        self,
        search_dir: str,
        patterns: List[str],
        dest_subpath: str,
        recursive: bool = True,
    ) -> int:
        """
        Collect files matching patterns.
        
        Args:
            search_dir: Directory to search.
            patterns: List of glob patterns.
            dest_subpath: Destination subpath.
            recursive: Whether to search recursively.
            
        Returns:
            Number of files collected.
        """
        collected = 0
        search_path = self._expand_path(search_dir)

        if not os.path.exists(search_path):
            return 0

        import glob as glob_module

        for pattern in patterns:
            if recursive:
                search_pattern = os.path.join(search_path, '**', pattern)
            else:
                search_pattern = os.path.join(search_path, pattern)

            for file_path in glob_module.glob(search_pattern, recursive=recursive):
                if os.path.isfile(file_path):
                    # Calculate relative path for destination
                    try:
                        rel_path = os.path.relpath(file_path, search_path)
                        dest_filename = rel_path.replace(os.sep, '_')
                    except Exception:
                        dest_filename = os.path.basename(file_path)

                    if self._collect_file(file_path, dest_subpath, dest_filename):
                        collected += 1

        return collected

    @abstractmethod
    def _get_time(self):
        return datetime.now()

    def collect(self) -> CollectionResult:
        """
        Perform the collection.
        
        Returns:
            CollectionResult with collection statistics.
        """
        pass

    def run(self) -> CollectionResult:
        """
        Run the collector with timing and error handling.
        
        Returns:
            CollectionResult.
        """
        self.result.start_time = datetime.now()

        try:
            self.collect()
        except Exception as e:
            self.result.add_error(f"Collector exception: {e}")
            logger.exception(f"Error in {self.category} collector")

        self.result.end_time = datetime.now()
        return self.result

    def should_collect(self) -> bool:
        """
        Check if this collector should run based on configuration.
        
        Returns:
            True if should collect.
        """
        categories = self.config.get('categories', [])

        # If no categories specified, collect based on level
        if not categories:
            return True

        # Check if this category is in the list
        return self.category in categories

    def _path_exists(self, path: str) -> bool:
        """Check if path exists in source."""
        return self.source.exists(path)

    def _list_dir(self, path: str) -> List[str]:
        """List directory contents."""
        return self.source.list_dir(path)

    def _is_file(self, path: str) -> bool:
        """Check if path is a file."""
        return self.source.is_file(path)

    def _get_file_size(self, path: str) -> int:
        """Get file size."""
        return self.source.file_size(path)

    def _extract_file(self, image_path: str, output_path: str) -> Tuple[bool, Optional[str]]:
        """Extract file from source to destination."""
        try:
            return self.source.extract(image_path, output_path)
        except Exception as e:
            return False, str(e)

    def _collect_relpaths(self, paths, dest_subpath: str = '') -> int:
        """Collect a list of source-relative file paths into ``dest_subpath``.

        Directory entries are expanded one level. Used by the declarative
        cross-OS collectors. Returns the number of files collected.
        """
        n = 0
        for rel in paths:
            rel = rel.lstrip('/')
            if not self._path_exists(rel):
                continue
            if self._is_file(rel):
                name = os.path.basename(rel.rstrip('/')) or rel.replace('/', '_')
                if self._collect_file(rel, dest_subpath, name):
                    n += 1
            else:
                for entry in self._list_dir(rel):
                    if entry in ('.', '..'):
                        continue
                    child = f"{rel}/{entry}"
                    if self._is_file(child) and self._collect_file(child, dest_subpath, entry):
                        n += 1
        return n

    def _register_derived_output(self, path: str) -> bool:
        """Register a collector-produced output file (inventory, scan results, …)
        with the manifest so it is hashed and included in the bundle/ZIP.

        Unlike ``_collect_file`` (which copies a source artifact), this attributes
        an already-written local file under ``output_root`` to this category.
        """
        try:
            size = os.path.getsize(path)
            hr = hash_file_streaming(path)
            rel = os.path.relpath(path, self.output_root)
            self.manifest.add_entry(
                source_path='<derived>', dest_path=rel, status='success',
                category=self.category, md5=hr.md5, sha256=hr.sha256, size_bytes=size,
            )
            self.result.files_collected += 1
            self.result.total_bytes += size
            return True
        except Exception as e:
            self.result.add_error(f"could not register derived output {path}: {e}")
            return False

    def _collect_dir_contents(
        self,
        source_dir: str,
        dest_subpath: str,
        pattern: str = '*',
    ) -> int:
        """Collect directory contents with error handling."""
        collected = 0
        try:
            if not self._path_exists(source_dir):
                return 0

            entries = self._list_dir(source_dir)

            for entry_name in entries:
                try:
                    if pattern == '*' or entry_name.endswith(pattern.lstrip('*')):
                        src_path = f"{source_dir}/{entry_name}"
                        if self._path_exists(src_path):
                            if self._collect_file(src_path, dest_subpath, entry_name):
                                collected += 1
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Error collecting dir {source_dir}: {e}")

        return collected
