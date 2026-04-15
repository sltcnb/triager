"""
Hashing utilities for ForensicHarvester.

This module provides file hashing functionality with support for multiple
algorithms and streaming for large files.
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional, List, BinaryIO
from dataclasses import dataclass

from utils.constants import DEFAULT_CHUNK_SIZE, HASH_ALGORITHMS

logger = logging.getLogger(__name__)


@dataclass
class HashResult:
    """Result of a file hashing operation."""
    file_path: str
    md5: Optional[str] = None
    sha256: Optional[str] = None
    error: Optional[str] = None
    size: int = 0


def calculate_hash(
    file_path: str,
    algorithm: str = 'sha256',
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Optional[str]:
    """
    Calculate the hash of a file.
    
    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm to use.
        chunk_size: Size of chunks for streaming.
        
    Returns:
        Hex digest string or None if error.
    """
    try:
        hasher = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        
        return hasher.hexdigest()
        
    except Exception as e:
        logger.debug(f"Error hashing {file_path} with {algorithm}: {e}")
        return None


def calculate_multiple_hashes(
    file_path: str,
    algorithms: List[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, str | None]:
    """
    Calculate multiple hashes of a file in a single pass.
    
    Args:
        file_path: Path to the file.
        algorithms: List of hash algorithms to use.
        chunk_size: Size of chunks for streaming.
        
    Returns:
        Dictionary of algorithm -> hex digest.
    """
    if algorithms is None:
        algorithms = HASH_ALGORITHMS
    
    try:
        # Create hashers for each algorithm
        hashers = {algo: hashlib.new(algo) for algo in algorithms}
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
        
    except Exception as e:
        logger.debug(f"Error calculating hashes for {file_path}: {e}")
        return {algo: None for algo in algorithms}


def hash_file_streaming(
    file_path: str,
    algorithms: List[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> HashResult:
    """
    Hash a file with multiple algorithms in a streaming fashion.
    
    Args:
        file_path: Path to the file.
        algorithms: List of hash algorithms.
        chunk_size: Size of chunks for streaming.
        
    Returns:
        HashResult object with hashes and metadata.
    """
    if algorithms is None:
        algorithms = HASH_ALGORITHMS
    
    try:
        # Get file size
        file_size = Path(file_path).stat().st_size
        
        # Create hashers
        hashers = {algo: hashlib.new(algo) for algo in algorithms}
        
        # Stream through file
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        return HashResult(
            file_path=file_path,
            md5=hashers.get('md5', hashlib.md5()).hexdigest() if 'md5' in hashers else None,
            sha256=hashers.get('sha256', hashlib.sha256()).hexdigest() if 'sha256' in hashers else None,
            size=file_size,
        )
        
    except Exception as e:
        logger.error(f"Error hashing {file_path}: {e}")
        return HashResult(
            file_path=file_path,
            error=str(e),
        )


def verify_hash(
    file_path: str,
    expected_hash: str,
    algorithm: str = 'sha256',
) -> bool:
    """
    Verify a file's hash against an expected value.
    
    Args:
        file_path: Path to the file.
        expected_hash: Expected hash value.
        algorithm: Hash algorithm used.
        
    Returns:
        True if hash matches, False otherwise.
    """
    try:
        actual_hash = calculate_hash(file_path, algorithm)
        if actual_hash is None:
            return False
        return actual_hash.lower() == expected_hash.lower()
    except Exception as e:
        logger.error(f"Error verifying hash for {file_path}: {e}")
        return False


def calculate_hashes_for_files(
    file_paths: List[str],
    algorithms: List[str] | None = None,
    parallel: bool = False,
) -> List[HashResult]:
    """
    Calculate hashes for multiple files.
    
    Args:
        file_paths: List of file paths.
        algorithms: List of hash algorithms.
        parallel: Whether to process in parallel (not implemented).
        
    Returns:
        List of HashResult objects.
    """
    results = []
    
    for file_path in file_paths:
        result = hash_file_streaming(file_path, algorithms)
        results.append(result)
    
    return results


def get_file_hash_csv_header() -> str:
    """
    Get the CSV header for hash results.
    
    Returns:
        CSV header string.
    """
    return "file_path,md5,sha256,size_bytes,error"


def hash_result_to_csv(result: HashResult) -> str:
    """
    Convert a HashResult to CSV format.
    
    Args:
        result: HashResult object.
        
    Returns:
        CSV row string.
    """
    md5 = result.md5 or ''
    sha256 = result.sha256 or ''
    error = result.error or ''
    
    # Escape commas and quotes in file path
    file_path = result.file_path.replace('"', '""')
    if ',' in file_path or '"' in file_path:
        file_path = f'"{file_path}"'
    
    return f"{file_path},{md5},{sha256},{result.size},{error}"
