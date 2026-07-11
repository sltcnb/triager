"""
Manifest utilities for Triager.

This module handles the collection manifest that tracks all collected files,
their hashes, metadata, and collection status.
"""

import json
import csv
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


logger = logging.getLogger(__name__)


@dataclass
class CollectionEntry:
    """Represents a single collected file in the manifest."""
    source_path: str
    dest_path: str
    md5: Optional[str]
    sha256: Optional[str]
    size_bytes: int
    source_created: Optional[str]
    source_modified: Optional[str]
    source_accessed: Optional[str]
    collection_time: str
    status: str  # 'success', 'failed', 'skipped'
    error: Optional[str]
    category: str
    level: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_csv_row(self) -> List:
        """Convert to CSV row."""
        return [
            self.source_path,
            self.dest_path,
            self.md5 or '',
            self.sha256 or '',
            self.size_bytes,
            self.source_created or '',
            self.source_modified or '',
            self.source_accessed or '',
            self.collection_time,
            self.status,
            self.error or '',
            self.category,
            self.level,
        ]


class CollectionManifest:
    """Manages the collection manifest."""
    
    CSV_HEADERS = [
        'source_path', 'dest_path', 'md5', 'sha256', 'size_bytes',
        'source_created', 'source_modified', 'source_accessed',
        'collection_time', 'status', 'error', 'category', 'level'
    ]
    
    def __init__(self, output_dir: str, level: str):
        """
        Initialize the manifest.
        
        Args:
            output_dir: Output directory for manifest files.
            level: Collection level.
        """
        self.output_dir = output_dir
        self.level = level
        self.entries: List[CollectionEntry] = []
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'total_bytes': 0,
            'categories': {},
        }
    
    def add_entry(
        self,
        source_path: str,
        dest_path: str,
        status: str,
        category: str,
        md5: str | None = None,
        sha256: str | None = None,
        size_bytes: int = 0,
        source_created: str | None = None,
        source_modified: str | None = None,
        source_accessed: str | None = None,
        error: str | None = None,
    ) -> CollectionEntry:
        """
        Add an entry to the manifest.
        
        Args:
            source_path: Original source path.
            dest_path: Destination path in output.
            status: Collection status.
            category: Category name.
            md5: MD5 hash.
            sha256: SHA256 hash.
            size_bytes: File size.
            source_created: Source file created time.
            source_modified: Source file modified time.
            source_accessed: Source file accessed time.
            error: Error message if failed.
            
        Returns:
            Created CollectionEntry.
        """
        entry = CollectionEntry(
            source_path=source_path,
            dest_path=dest_path,
            md5=md5,
            sha256=sha256,
            size_bytes=size_bytes,
            source_created=source_created,
            source_modified=source_modified,
            source_accessed=source_accessed,
            collection_time=datetime.now().isoformat(),
            status=status,
            error=error,
            category=category,
            level=self.level,
        )
        
        self.entries.append(entry)
        
        # Update statistics
        self.stats['total_files'] += 1
        
        if status == 'success':
            self.stats['successful'] += 1
            self.stats['total_bytes'] += size_bytes
        elif status == 'failed':
            self.stats['failed'] += 1
            if error:
                self.errors.append(f"{source_path}: {error}")
        elif status == 'skipped':
            self.stats['skipped'] += 1
        
        # Update category stats
        if category not in self.stats['categories']:
            self.stats['categories'][category] = {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'bytes': 0,
            }
        
        self.stats['categories'][category]['total'] += 1
        if status == 'success':
            self.stats['categories'][category]['successful'] += 1
            self.stats['categories'][category]['bytes'] += size_bytes
        elif status == 'failed':
            self.stats['categories'][category]['failed'] += 1
        
        return entry
    
    def add_error(self, error: str):
        """Add a general error."""
        self.errors.append(error)
        logger.error(error)
    
    def add_warning(self, warning: str):
        """Add a warning."""
        self.warnings.append(warning)
        logger.warning(warning)
    
    def save_manifest_json(self) -> str:
        """
        Save the manifest as JSON.
        
        Returns:
            Path to saved manifest.
        """
        self.end_time = datetime.now()
        
        manifest_data = {
            'metadata': {
                'tool': 'Triager',
                'version': '1.0.0',
                'level': self.level,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration_seconds': (self.end_time - self.start_time).total_seconds(),
            },
            'statistics': self.stats,
            'errors': self.errors,
            'warnings': self.warnings,
            'files': [entry.to_dict() for entry in self.entries],
        }
        
        manifest_path = os.path.join(
            self.output_dir,
            'metadata',
            'collection_manifest.json'
        )
        
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest_data, f, indent=2, default=str)
        
        logger.info(f"Saved manifest to {manifest_path}")
        return manifest_path
    
    def save_manifest_csv(self) -> str:
        """
        Save the manifest as CSV.
        
        Returns:
            Path to saved CSV.
        """
        csv_path = os.path.join(
            self.output_dir,
            'metadata',
            'collected_files.csv'
        )
        
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(self.CSV_HEADERS)
            
            for entry in self.entries:
                writer.writerow(entry.to_csv_row())
        
        logger.info(f"Saved CSV manifest to {csv_path}")
        return csv_path
    
    def save_errors_log(self) -> str:
        """
        Save errors to a log file.
        
        Returns:
            Path to saved log.
        """
        log_path = os.path.join(
            self.output_dir,
            'metadata',
            'errors.log'
        )
        
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write("Triager Error Log\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Level: {self.level}\n\n")
            f.write(f"Total Errors: {len(self.errors)}\n")
            f.write(f"Total Warnings: {len(self.warnings)}\n\n")
            
            if self.errors:
                f.write("=" * 80 + "\n")
                f.write("ERRORS:\n")
                f.write("=" * 80 + "\n\n")
                for error in self.errors:
                    f.write(f"- {error}\n")
            
            if self.warnings:
                f.write("\n" + "=" * 80 + "\n")
                f.write("WARNINGS:\n")
                f.write("=" * 80 + "\n\n")
                for warning in self.warnings:
                    f.write(f"- {warning}\n")
        
        logger.info(f"Saved errors log to {log_path}")
        return log_path
    
    def get_summary(self) -> Dict:
        """
        Get a summary of the collection.
        
        Returns:
            Summary dictionary.
        """
        return {
            'total_files': self.stats['total_files'],
            'successful': self.stats['successful'],
            'failed': self.stats['failed'],
            'skipped': self.stats['skipped'],
            'total_bytes': self.stats['total_bytes'],
            'total_mb': self.stats['total_bytes'] / (1024 * 1024),
            'total_gb': self.stats['total_bytes'] / (1024 * 1024 * 1024),
            'categories': self.stats['categories'],
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
        }


def create_hash_csv(
    entries: List[CollectionEntry],
    output_path: str,
):
    """
    Create a CSV file with hashes of collected files.
    
    Args:
        entries: List of collection entries.
        output_path: Path for output CSV.
    """
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['file_path', 'md5', 'sha256', 'size_bytes'])
        
        for entry in entries:
            if entry.md5 or entry.sha256:
                writer.writerow([
                    entry.dest_path,
                    entry.md5 or '',
                    entry.sha256 or '',
                    entry.size_bytes,
                ])
