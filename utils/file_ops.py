"""
File operations utilities for Triager.

This module provides robust file copying, long path handling, timestamp preservation,
and error-resilient file operations.
"""

import os
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List
from dataclasses import dataclass

from utils.constants import (
    MAX_PATH_WINDOWS,
    DEFAULT_CHUNK_SIZE,
)

logger = logging.getLogger(__name__)


@dataclass
class FileMetadata:
    """File metadata information."""
    size: int
    created: datetime
    modified: datetime
    accessed: datetime
    attributes: int
    owner: Optional[str] = None
    permissions: Optional[str] = None


def extend_path(path: str) -> str:
    """
    Extend a path to support long filenames on Windows.
    
    Args:
        path: The file path to extend.
        
    Returns:
        The path with backslash prefix if needed.
    """
    if not path:
        return path
    
    # Convert to absolute path
    abs_path = os.path.abspath(path)
    
    # Check if already extended
    if abs_path.startswith('\\\\?\\'):
        return abs_path
    
    # Check if path exceeds MAX_PATH
    if len(abs_path) > 260:
        return '\\\\?\\' + abs_path
    
    return abs_path


def get_file_metadata(path: str) -> Optional[FileMetadata]:
    """
    Get metadata for a file.
    
    Args:
        path: Path to the file.
        
    Returns:
        FileMetadata object or None if file doesn't exist.
    """
    try:
        extended_path = extend_path(path)
        stat_info = os.stat(extended_path)
        
        return FileMetadata(
            size=stat_info.st_size,
            created=datetime.fromtimestamp(stat_info.st_ctime),
            modified=datetime.fromtimestamp(stat_info.st_mtime),
            accessed=datetime.fromtimestamp(stat_info.st_atime),
            attributes=0,  # Would need Windows API for full attributes
        )
    except (OSError, ValueError) as e:
        logger.debug(f"Failed to get metadata for {path}: {e}")
        return None


def copy_file_with_metadata(
    src: str,
    dst: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    preserve_timestamps: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Copy a file while preserving metadata and handling errors gracefully.
    
    Args:
        src: Source file path.
        dst: Destination file path.
        chunk_size: Size of chunks for streaming copy.
        preserve_timestamps: Whether to preserve file timestamps.
        
    Returns:
        Tuple of (success, error_message).
    """
    try:
        extended_src = extend_path(src)
        extended_dst = extend_path(dst)
        
        # Ensure destination directory exists
        dst_dir = os.path.dirname(extended_dst)
        if dst_dir and not os.path.exists(dst_dir):
            os.makedirs(dst_dir, exist_ok=True)
        
        # Check if source is a regular file
        if not os.path.isfile(extended_src):
            return False, "Source is not a regular file"

        # Perform the copy. copy2 preserves timestamps/metadata; plain copy
        # only preserves permissions, honouring preserve_timestamps=False.
        if preserve_timestamps:
            shutil.copy2(extended_src, extended_dst)
        else:
            shutil.copy(extended_src, extended_dst)
        
        # Verify the copy
        if not os.path.exists(extended_dst):
            return False, "Destination file was not created"
        
        # Verify size match
        src_size = os.path.getsize(extended_src)
        dst_size = os.path.getsize(extended_dst)
        if src_size != dst_size:
            return False, f"Size mismatch: source={src_size}, dest={dst_size}"
        
        return True, None
        
    except PermissionError as e:
        logger.warning(f"Permission denied copying {src}: {e}")
        return False, f"Permission denied: {str(e)}"
    except FileNotFoundError as e:
        logger.warning(f"File not found {src}: {e}")
        return False, f"File not found: {str(e)}"
    except OSError as e:
        logger.warning(f"OS error copying {src}: {e}")
        return False, f"OS error: {str(e)}"
    except Exception as e:
        logger.warning(f"Unexpected error copying {src}: {e}")
        return False, f"Unexpected error: {str(e)}"


def copy_file_streaming(
    src: str,
    dst: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Tuple[bool, Optional[str]]:
    """
    Copy a file using streaming to handle large files efficiently.
    
    Args:
        src: Source file path.
        dst: Destination file path.
        chunk_size: Size of chunks for streaming.
        
    Returns:
        Tuple of (success, error_message).
    """
    try:
        extended_src = extend_path(src)
        extended_dst = extend_path(dst)
        
        # Ensure destination directory exists
        dst_dir = os.path.dirname(extended_dst)
        if dst_dir and not os.path.exists(dst_dir):
            os.makedirs(dst_dir, exist_ok=True)
        
        with open(extended_src, 'rb') as fsrc:
            with open(extended_dst, 'wb') as fdst:
                while True:
                    chunk = fsrc.read(chunk_size)
                    if not chunk:
                        break
                    fdst.write(chunk)
        
        return True, None
        
    except Exception as e:
        logger.warning(f"Error streaming copy {src}: {e}")
        return False, str(e)


def list_files(
    directory: str,
    pattern: str = '*',
    recursive: bool = True,
    include_hidden: bool = True,
    include_system: bool = True,
) -> List[str]:
    """
    List files in a directory with optional filtering.
    
    Args:
        directory: Directory to search.
        pattern: Glob pattern to match files.
        recursive: Whether to search recursively.
        include_hidden: Whether to include hidden files.
        include_system: Whether to include system files.
        
    Returns:
        List of file paths.
    """
    try:
        extended_dir = extend_path(directory)
        files = []
        
        if recursive:
            pattern_path = f"**/{pattern}"
        else:
            pattern_path = pattern
        
        for path in Path(extended_dir).glob(pattern_path):
            if path.is_file():
                # Filter hidden/system files if needed
                if not include_hidden:
                    # Check if path contains hidden components
                    parts = path.relative_to(extended_dir).parts
                    if any(part.startswith('.') for part in parts):
                        continue
                
                files.append(str(path))
        
        return sorted(files)
        
    except Exception as e:
        logger.debug(f"Error listing files in {directory}: {e}")
        return []


def get_directory_size(directory: str) -> int:
    """
    Calculate the total size of a directory.
    
    Args:
        directory: Directory path.
        
    Returns:
        Total size in bytes.
    """
    total_size = 0
    try:
        extended_dir = extend_path(directory)
        for entry in os.scandir(extended_dir):
            if entry.is_file():
                total_size += entry.stat().st_size
            elif entry.is_dir():
                total_size += get_directory_size(str(entry.path))
    except Exception as e:
        logger.debug(f"Error calculating directory size: {e}")
    
    return total_size


def safe_remove(path: str) -> bool:
    """
    Safely remove a file or directory.
    
    Args:
        path: Path to remove.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        extended_path = extend_path(path)
        if os.path.isfile(extended_path):
            os.remove(extended_path)
        elif os.path.isdir(extended_path):
            shutil.rmtree(extended_path)
        return True
    except Exception as e:
        logger.debug(f"Failed to remove {path}: {e}")
        return False


def normalize_path(path: str) -> str:
    """
    Normalize a file path for consistent handling.
    
    Args:
        path: Path to normalize.
        
    Returns:
        Normalized path.
    """
    # Convert to absolute path
    abs_path = os.path.abspath(path)
    
    # Normalize separators
    abs_path = os.path.normpath(abs_path)
    
    return abs_path


def get_relative_path(path: str, base: str) -> str:
    """
    Get the relative path from a base directory.
    
    Args:
        path: Full path.
        base: Base directory.
        
    Returns:
        Relative path.
    """
    try:
        return os.path.relpath(path, base)
    except ValueError:
        # Different drives on Windows
        return path


def ensure_directory(path: str) -> bool:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path.
        
    Returns:
        True if successful or already exists, False otherwise.
    """
    try:
        extended_path = extend_path(path)
        os.makedirs(extended_path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {path}: {e}")
        return False


def is_valid_file_path(path: str) -> bool:
    """
    Check if a path is a valid file path.
    
    Args:
        path: Path to check.
        
    Returns:
        True if valid, False otherwise.
    """
    if not path:
        return False
    
    # Check for invalid characters
    invalid_chars = '<>"|?*'
    if any(char in path for char in invalid_chars):
        return False
    
    # Check length
    if len(path) > MAX_PATH_WINDOWS:
        return False
    
    return True
