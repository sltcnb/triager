"""
Privilege utilities for Triager.

This module provides Windows privilege management for acquiring
SeBackupPrivilege and SeSecurityPrivilege needed for forensic collection.
"""

import ctypes
import logging
from typing import Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Windows constants
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000
TOKEN_QUERY = 0x00000008
TOKEN_ADJUST_PRIVILEGES = 0x00000020
ERROR_SUCCESS = 0

# Privilege names
SE_BACKUP_PRIVILEGE = "SeBackupPrivilege"
SE_SECURITY_PRIVILEGE = "SeSecurityPrivilege"
SE_RESTORE_PRIVILEGE = "SeRestorePrivilege"


@dataclass
class PrivilegeState:
    """State of a Windows privilege."""
    name: str
    enabled: bool
    available: bool


def get_token_handle(process_handle=None) -> Optional[int]:
    """
    Get the access token handle for the current process.
    
    Returns:
        Token handle or None if failed.
    """
    try:
        if process_handle is None:
            process_handle = ctypes.windll.kernel32.GetCurrentProcess()
        
        token_handle = ctypes.c_void_p()
        
        result = ctypes.windll.advapi32.OpenProcessToken(
            process_handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token_handle),
        )
        
        if result == 0:
            logger.error(f"Failed to open process token: {ctypes.get_last_error()}")
            return None
        
        return token_handle.value
        
    except Exception as e:
        logger.error(f"Error getting token handle: {e}")
        return None


def lookup_privilege_value(privilege_name: str) -> Optional[ctypes.Structure]:
    """
    Look up the LUID for a privilege.
    
    Args:
        privilege_name: Name of the privilege.
        
    Returns:
        LUID structure or None.
    """
    try:
        luid = ctypes.c_longlong()
        
        result = ctypes.windll.advapi32.LookupPrivilegeValueW(
            None,
            privilege_name,
            ctypes.byref(luid),
        )
        
        if result == 0:
            logger.error(f"Failed to lookup privilege {privilege_name}")
            return None
        
        return luid
        
    except Exception as e:
        logger.error(f"Error looking up privilege: {e}")
        return None


def enable_privilege(privilege_name: str) -> bool:
    """
    Enable a Windows privilege for the current process.
    
    Args:
        privilege_name: Name of the privilege to enable.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        # Get token handle
        token_handle = get_token_handle()
        if token_handle is None:
            return False
        
        # Look up privilege LUID
        luid = lookup_privilege_value(privilege_name)
        if luid is None:
            return False
        
        # Create TOKEN_PRIVILEGES structure
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", ctypes.c_longlong),
                ("Attributes", ctypes.c_ulong),
            ]
        
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.c_ulong),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]
        
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid.value
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        
        # Adjust token privileges
        result = ctypes.windll.advapi32.AdjustTokenPrivileges(
            token_handle,
            False,
            ctypes.byref(tp),
            0,
            None,
            None,
        )
        
        if result == 0:
            logger.error(f"Failed to adjust privileges: {ctypes.get_last_error()}")
            return False
        
        # Check for errors
        last_error = ctypes.get_last_error()
        if last_error != ERROR_SUCCESS:
            logger.warning(f"AdjustTokenPrivileges returned error: {last_error}")
            return False
        
        logger.info(f"Successfully enabled privilege: {privilege_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error enabling privilege {privilege_name}: {e}")
        return False


def disable_privilege(privilege_name: str) -> bool:
    """
    Disable a Windows privilege.
    
    Args:
        privilege_name: Name of the privilege to disable.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        token_handle = get_token_handle()
        if token_handle is None:
            return False
        
        luid = lookup_privilege_value(privilege_name)
        if luid is None:
            return False
        
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", ctypes.c_longlong),
                ("Attributes", ctypes.c_ulong),
            ]
        
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.c_ulong),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]
        
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid.value
        tp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED
        
        result = ctypes.windll.advapi32.AdjustTokenPrivileges(
            token_handle,
            False,
            ctypes.byref(tp),
            0,
            None,
            None,
        )
        
        return result != 0
        
    except Exception as e:
        logger.error(f"Error disabling privilege: {e}")
        return False


def check_privilege_state(privilege_name: str) -> PrivilegeState:
    """
    Check the state of a privilege.
    
    Args:
        privilege_name: Name of the privilege.
        
    Returns:
        PrivilegeState object.
    """
    try:
        token_handle = get_token_handle()
        if token_handle is None:
            return PrivilegeState(
                name=privilege_name,
                enabled=False,
                available=False,
            )
        
        # Get token information
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = []
        
        # First call to get required buffer size
        required_size = ctypes.c_ulong()
        ctypes.windll.advapi32.GetTokenInformation(
            token_handle,
            3,  # TokenPrivileges
            None,
            0,
            ctypes.byref(required_size),
        )
        
        # Allocate buffer
        buffer = ctypes.create_string_buffer(required_size.value)
        
        result = ctypes.windll.advapi32.GetTokenInformation(
            token_handle,
            3,
            buffer,
            len(buffer),
            ctypes.byref(required_size),
        )
        
        if result == 0:
            return PrivilegeState(
                name=privilege_name,
                enabled=False,
                available=False,
            )
        
        # Parse privileges (simplified)
        return PrivilegeState(
            name=privilege_name,
            enabled=False,  # Would need full parsing
            available=True,
        )
        
    except Exception as e:
        logger.debug(f"Error checking privilege state: {e}")
        return PrivilegeState(
            name=privilege_name,
            enabled=False,
            available=False,
        )


def enable_backup_privileges() -> Tuple[bool, bool]:
    """
    Enable SeBackupPrivilege and SeSecurityPrivilege.
    
    Returns:
        Tuple of (backup_enabled, security_enabled).
    """
    backup_enabled = enable_privilege(SE_BACKUP_PRIVILEGE)
    security_enabled = enable_privilege(SE_SECURITY_PRIVILEGE)
    
    return backup_enabled, security_enabled


def is_running_as_admin() -> bool:
    """
    Check if the current process is running as administrator.
    
    Returns:
        True if running as admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin_privileges() -> bool:
    """
    Request administrator privileges by re-launching with elevation.
    
    Returns:
        True if already admin or successfully relaunched, False otherwise.
    """
    if is_running_as_admin():
        return True
    
    try:
        import sys

        # Relaunch with elevation
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1,  # SW_SHOWNORMAL
        )
        
        return ret > 32
        
    except Exception as e:
        logger.error(f"Failed to request admin privileges: {e}")
        return False
