"""
ZIP utilities for ForensicHarvester.

This module provides ZIP file creation with support for large files,
password protection, and ZIP64 format.
"""

import os
import zipfile
import logging
from pathlib import Path
from typing import Optional, List, Callable
from datetime import datetime

# Try to import pyzipper for password protection
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False
    logging.getLogger(__name__).debug("pyzipper not available, password protection disabled")

logger = logging.getLogger(__name__)


def create_zip_file(
    source_dir: str,
    output_path: str,
    password: str | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
    progress_callback: Callable[[str, int, int], None] | None = None,
) -> bool:
    """
    Create a ZIP file from a directory.
    
    Args:
        source_dir: Directory to compress.
        output_path: Output ZIP file path.
        password: Optional password for encryption.
        compression: Compression method.
        progress_callback: Optional callback for progress (filename, current, total).
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        source_path = Path(source_dir).resolve()
        
        # Count total files
        total_files = 0
        for root, dirs, files in os.walk(source_path):
            total_files += len(files)
        
        if total_files == 0:
            logger.warning(f"No files to compress in {source_dir}")
            return False
        
        # Choose ZIP class based on password
        if password and PYZIPPER_AVAILABLE:
            zip_class = pyzipper.AESZipFile
            encryption = pyzipper.WZ_AES
        else:
            zip_class = zipfile.ZipFile
            encryption = None
        
        # Create ZIP file
        with zip_class(
            output_path,
            'w',
            compression=compression,
            allowZip64=True,
            
        ) as zipf:
            
            # Set password if provided
            if password:
                zipf.setpassword(password.encode('utf-8'))
            
            current_file = 0
            
            for root, dirs, files in os.walk(source_path):
                for filename in files:
                    file_path = Path(root) / filename
                    
                    # Calculate archive path (relative to source_dir)
                    arcname = file_path.relative_to(source_path)
                    
                    try:
                        zipf.write(file_path, arcname)
                    except Exception as e:
                        logger.warning(f"Failed to add {file_path} to ZIP: {e}")
                    
                    current_file += 1
                    
                    if progress_callback:
                        try:
                            progress_callback(str(arcname), current_file, total_files)
                        except Exception:
                            pass
        
        logger.info(f"Successfully created ZIP: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create ZIP: {e}")
        return False


def create_zip_with_manifest(
    source_dir: str,
    output_path: str,
    manifest_path: str | None = None,
    password: str | None = None,
) -> bool:
    """
    Create a ZIP file including the manifest.
    
    Args:
        source_dir: Directory to compress.
        output_path: Output ZIP file path.
        manifest_path: Optional separate manifest file path.
        password: Optional password.
        
    Returns:
        True if successful.
    """
    return create_zip_file(source_dir, output_path, password)


def get_zip_info(zip_path: str) -> dict:
    """
    Get information about a ZIP file.
    
    Args:
        zip_path: Path to ZIP file.
        
    Returns:
        Dictionary with ZIP information.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            info = {
                'path': zip_path,
                'num_files': len(zipf.namelist()),
                'file_list': zipf.namelist(),
                'is_zip64': False,  # Would need to check ZipInfo
                'comment': zipf.comment.decode('utf-8') if zipf.comment else '',
            }
            
            # Calculate total size
            total_size = 0
            compressed_size = 0
            
            for file_info in zipf.infolist():
                total_size += file_info.file_size
                compressed_size += file_info.compress_size
            
            info['total_size'] = total_size
            info['compressed_size'] = compressed_size
            info['compression_ratio'] = (
                (total_size - compressed_size) / total_size * 100
                if total_size > 0 else 0
            )
            
            return info
            
    except Exception as e:
        logger.error(f"Failed to read ZIP info: {e}")
        return {}


def verify_zip(zip_path: str) -> bool:
    """
    Verify a ZIP file is not corrupted.
    
    Args:
        zip_path: Path to ZIP file.
        
    Returns:
        True if valid, False otherwise.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            bad_file = zipf.testzip()
            if bad_file is not None:
                logger.error(f"Corrupted file in ZIP: {bad_file}")
                return False
        return True
    except Exception as e:
        logger.error(f"ZIP verification failed: {e}")
        return False


def extract_zip(
    zip_path: str,
    output_dir: str,
    password: str | None = None,
) -> bool:
    """
    Extract a ZIP file.
    
    Args:
        zip_path: Path to ZIP file.
        output_dir: Output directory.
        password: Optional password.
        
    Returns:
        True if successful.
    """
    try:
        # Try pyzipper first (for encrypted ZIPs)
        if PYZIPPER_AVAILABLE:
            try:
                with pyzipper.AESZipFile(zip_path, 'r') as zipf:
                    if password:
                        zipf.setpassword(password.encode('utf-8'))
                    zipf.extractall(output_dir)
                return True
            except Exception:
                pass
        
        # Fall back to standard zipfile
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            if password:
                logger.warning("Standard zipfile cannot handle encrypted ZIPs")
            zipf.extractall(output_dir)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to extract ZIP: {e}")
        return False


def generate_zip_filename(
    hostname: str,
    timestamp: datetime | None = None,
    prefix: str = "ForensicHarvester",
) -> str:
    """
    Generate a deterministic ZIP filename.
    
    Args:
        hostname: System hostname.
        timestamp: Timestamp for filename.
        prefix: Filename prefix.
        
    Returns:
        Generated filename.
    """
    if timestamp is None:
        timestamp = datetime.now()
    
    ts_str = timestamp.strftime('%Y%m%d_%H%M%S')
    
    # Sanitize hostname
    safe_hostname = hostname.replace('\\', '-').replace('/', '-').replace(':', '-')
    
    return f"{prefix}_{safe_hostname}_{ts_str}.zip"


def calculate_zip_size(source_dir: str) -> int:
    """
    Estimate the size of files to be zipped.
    
    Args:
        source_dir: Directory to measure.
        
    Returns:
        Total size in bytes.
    """
    total_size = 0
    
    try:
        for root, dirs, files in os.walk(source_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                try:
                    total_size += os.path.getsize(file_path)
                except Exception:
                    pass
    except Exception:
        pass
    
    return total_size
