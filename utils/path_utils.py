"""
Path utilities for Triager.

This module provides path expansion, normalization, and cross-platform
path handling utilities.
"""

import os
import logging
from typing import List, Optional, Dict
from datetime import datetime


logger = logging.getLogger(__name__)


def expand_environment_variables(path: str) -> str:
    """
    Expand environment variables in a path.
    
    Args:
        path: Path with environment variables.
        
    Returns:
        Expanded path.
    """
    try:
        return os.path.expandvars(path)
    except Exception as e:
        logger.debug(f"Failed to expand variables in {path}: {e}")
        return path


def expand_windows_paths(path: str, system_root: str | None = None) -> str:
    """
    Expand Windows-specific path variables.
    
    Args:
        path: Path to expand.
        system_root: System root directory (default: %SYSTEMROOT%).
        
    Returns:
        Expanded path.
    """
    if not system_root:
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    
    # Replace common Windows path variables
    replacements = {
        '%SYSTEMROOT%': system_root,
        '%WINDIR%': system_root,
        '%PROGRAMFILES%': os.environ.get('ProgramFiles', 'C:\\Program Files'),
        '%PROGRAMFILES(X86)%': os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
        '%PROGRAMDATA%': os.environ.get('ProgramData', 'C:\\ProgramData'),
        '%APPDATA%': os.environ.get('AppData', ''),
        '%LOCALAPPDATA%': os.environ.get('LocalAppData', ''),
        '%TEMP%': os.environ.get('Temp', ''),
        '%TMP%': os.environ.get('Tmp', ''),
        '%USERPROFILE%': os.environ.get('UserProfile', ''),
        '%HOMEDRIVE%': os.environ.get('HOMEDRIVE', 'C:'),
        '%HOMEPATH%': os.environ.get('HOMEPATH', '\\Users'),
        '%SYSTEMDRIVE%': os.environ.get('SystemDrive', 'C:'),
    }
    
    expanded = path
    for var, value in replacements.items():
        expanded = expanded.replace(var, value)
    
    # Also handle %VAR% format
    expanded = os.path.expandvars(expanded)
    
    return expanded


def normalize_separators(path: str) -> str:
    """
    Normalize path separators to OS-standard.
    
    Args:
        path: Path to normalize.
        
    Returns:
        Normalized path.
    """
    # Convert forward slashes to backslashes on Windows
    if os.name == 'nt':
        return path.replace('/', '\\')
    else:
        return path.replace('\\', '/')


def ensure_absolute_path(path: str, base: str | None = None) -> str:
    """
    Ensure a path is absolute.
    
    Args:
        path: Path to make absolute.
        base: Base directory for relative paths.
        
    Returns:
        Absolute path.
    """
    if os.path.isabs(path):
        return path
    
    if base is None:
        base = os.getcwd()
    
    return os.path.join(base, path)


def sanitize_filename(filename: str, replacement: str = '_') -> str:
    """
    Sanitize a filename by removing invalid characters.
    
    Args:
        filename: Original filename.
        replacement: Character to replace invalid chars with.
        
    Returns:
        Sanitized filename.
    """
    # Windows invalid characters
    invalid_chars = '<>:"|?*'
    
    sanitized = filename
    for char in invalid_chars:
        sanitized = sanitized.replace(char, replacement)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 255:
        # Preserve extension
        if '.' in sanitized:
            name, ext = sanitized.rsplit('.', 1)
            max_name = 255 - len(ext) - 1
            sanitized = name[:max_name] + '.' + ext
        else:
            sanitized = sanitized[:255]
    
    return sanitized or 'unnamed'


def get_path_timestamps(path: str) -> Dict[str, Optional[str]]:
    """
    Get timestamps for a file path.
    
    Args:
        path: Path to get timestamps for.
        
    Returns:
        Dictionary with created, modified, accessed timestamps.
    """
    try:
        stat = os.stat(path)
        return {
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
        }
    except Exception:
        return {
            'created': None,
            'modified': None,
            'accessed': None,
        }


def build_output_path(
    base_dir: str,
    category: str,
    subpath: str = '',
    filename: str = '',
) -> str:
    """
    Build a deterministic output path.
    
    Args:
        base_dir: Base output directory.
        category: Category folder (e.g., 'registry', 'eventlogs').
        subpath: Subpath within category.
        filename: Filename.
        
    Returns:
        Full output path.
    """
    parts = [base_dir, category]
    
    if subpath:
        parts.append(subpath)
    
    if filename:
        parts.append(filename)
    
    return os.path.join(*parts)


def get_user_profiles_path(drive: str | None = None) -> str:
    """
    Get the path to user profiles directory.
    
    Args:
        drive: Drive letter (default: system drive).
        
    Returns:
        Path to user profiles.
    """
    if drive is None:
        drive = os.environ.get('SystemDrive', 'C:')
    
    return os.path.join(drive, 'Users')


def get_program_data_path() -> str:
    """
    Get the ProgramData directory path.
    
    Returns:
        Path to ProgramData.
    """
    return os.environ.get('ProgramData', 'C:\\ProgramData')


def enumerate_user_profiles(
    profiles_root: str | None = None,
    exclude_system: bool = True,
) -> List[str]:
    """
    Enumerate user profile directories.
    
    Args:
        profiles_root: Root directory for profiles.
        exclude_system: Whether to exclude system accounts.
        
    Returns:
        List of usernames.
    """
    if profiles_root is None:
        profiles_root = get_user_profiles_path()
    
    system_accounts = {
        'Default',
        'Default User',
        'All Users',
        'Public',
    }
    
    profiles = []
    
    try:
        if not os.path.exists(profiles_root):
            return profiles
        
        for entry in os.listdir(profiles_root):
            profile_path = os.path.join(profiles_root, entry)
            
            if not os.path.isdir(profile_path):
                continue
            
            if exclude_system and entry in system_accounts:
                continue
            
            profiles.append(entry)
            
    except Exception as e:
        logger.debug(f"Error enumerating profiles: {e}")
    
    return profiles


def is_path_under_directory(path: str, directory: str) -> bool:
    """
    Check if a path is under a directory.
    
    Args:
        path: Path to check.
        directory: Directory to check against.
        
    Returns:
        True if path is under directory.
    """
    try:
        rel_path = os.path.relpath(path, directory)
        return not rel_path.startswith('..')
    except Exception:
        return False


def get_common_paths() -> Dict[str, str]:
    """
    Get common Windows paths.
    
    Returns:
        Dictionary of path names to paths.
    """
    return {
        'system_root': os.environ.get('SystemRoot', 'C:\\Windows'),
        'system32': os.path.join(
            os.environ.get('SystemRoot', 'C:\\Windows'),
            'System32'
        ),
        'syswow64': os.path.join(
            os.environ.get('SystemRoot', 'C:\\Windows'),
            'SysWOW64'
        ),
        'program_files': os.environ.get('ProgramFiles', 'C:\\Program Files'),
        'program_files_x86': os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
        'program_data': os.environ.get('ProgramData', 'C:\\ProgramData'),
        'temp': os.environ.get('Temp', ''),
        'user_profile': os.environ.get('UserProfile', ''),
    }
