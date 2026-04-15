"""
System information utilities for ForensicHarvester.

This module collects system information about the target machine.
"""

import os
import platform
import socket
import logging
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """System information data."""
    hostname: str
    fqdn: str
    platform: str
    platform_release: str
    platform_version: str
    architecture: str
    processor: str
    cpu_count: int
    total_memory_bytes: int
    boot_time: Optional[str]
    username: str
    user_domain: Optional[str]
    is_admin: bool
    system_root: str
    system_drive: str
    collection_time: str
    network_interfaces: List[Dict]
    disk_info: List[Dict]
    os_install_date: Optional[str]
    timezone: str
    uptime_seconds: Optional[int]


def get_hostname() -> str:
    """Get the system hostname."""
    return socket.gethostname()


def get_fqdn() -> str:
    """Get the fully qualified domain name."""
    try:
        return socket.getfqdn()
    except Exception:
        return get_hostname()


def get_platform_info() -> Dict[str, str]:
    """Get platform information."""
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'architecture': platform.architecture()[0],
    }


def get_memory_info() -> int:
    """Get total system memory in bytes."""
    try:
        if os.name == 'nt':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulonglong = ctypes.c_ulonglong
            
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', c_ulonglong),
                    ('ullAvailPhys', c_ulonglong),
                    ('ullTotalPageFile', c_ulonglong),
                    ('ullAvailPageFile', c_ulonglong),
                    ('ullTotalVirtual', c_ulonglong),
                    ('ullAvailVirtual', c_ulonglong),
                    ('ullAvailExtendedVirtual', c_ulonglong),
                ]
            
            mem_status = MEMORYSTATUSEX()
            mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
                return mem_status.ullTotalPhys
    except Exception:
        pass
    
    # Fallback for non-Windows
    try:
        import psutil
        return psutil.virtual_memory().total
    except Exception:
        pass
    
    return 0


def get_boot_time() -> Optional[str]:
    """Get system boot time."""
    try:
        if os.name == 'nt':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            boot_time = datetime.fromtimestamp(
                ctypes.c_double(kernel32.GetTickCount64() / 1000.0)
            )
            return boot_time.isoformat()
    except Exception:
        pass
    
    try:
        import psutil
        return datetime.fromtimestamp(psutil.boot_time()).isoformat()
    except Exception:
        pass
    
    return None


def get_uptime_seconds() -> Optional[int]:
    """Get system uptime in seconds."""
    try:
        if os.name == 'nt':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            return int(kernel32.GetTickCount64() / 1000)
    except Exception:
        pass
    
    try:
        import psutil
        return int(datetime.now().timestamp() - psutil.boot_time())
    except Exception:
        pass
    
    return None


def get_username() -> str:
    """Get current username."""
    return os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USERNAME', 'unknown')


def is_running_as_admin() -> bool:
    """Check if running as administrator."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_network_interfaces() -> List[Dict]:
    """Get network interface information."""
    interfaces = []
    
    try:
        import psutil
        net_if_addrs = psutil.net_if_addrs()
        
        for iface_name, addrs in net_if_addrs.items():
            iface_info = {
                'name': iface_name,
                'addresses': [],
            }
            
            for addr in addrs:
                addr_info = {
                    'family': addr.family.name if hasattr(addr.family, 'name') else str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                }
                iface_info['addresses'].append(addr_info)
            
            interfaces.append(iface_info)
            
    except Exception as e:
        logger.debug(f"Failed to get network interfaces: {e}")
        
        # Fallback using socket
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            interfaces.append({
                'name': 'primary',
                'addresses': [{
                    'family': 'IPv4',
                    'address': ip_address,
                }],
            })
        except Exception:
            pass
    
    return interfaces


def get_disk_info() -> List[Dict]:
    """Get disk information."""
    disks = []
    
    try:
        if os.name == 'nt':
            import ctypes
            
            drives = []
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drives.append(chr(ord('A') + i) + ':\\')
            
            for drive in drives:
                try:
                    free_bytes = ctypes.c_ulonglong()
                    total_bytes = ctypes.c_ulonglong()
                    total_free_bytes = ctypes.c_ulonglong()
                    
                    result = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        drive,
                        ctypes.byref(free_bytes),
                        ctypes.byref(total_bytes),
                        ctypes.byref(total_free_bytes),
                    )
                    
                    if result:
                        disks.append({
                            'drive': drive,
                            'total_bytes': total_bytes.value,
                            'free_bytes': free_bytes.value,
                        })
                except Exception:
                    pass
    except Exception:
        pass
    
    # Fallback for non-Windows
    try:
        import psutil
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total_bytes': usage.total,
                    'free_bytes': usage.free,
                })
            except Exception:
                pass
    except Exception:
        pass
    
    return disks


def get_os_install_date() -> Optional[str]:
    """Get OS installation date."""
    try:
        if os.name == 'nt':
            import winreg
            
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0,
                winreg.KEY_READ,
            )
            
            try:
                install_date, _ = winreg.QueryValueEx(key, 'InstallDate')
                return datetime.fromtimestamp(install_date).isoformat()
            finally:
                winreg.CloseKey(key)
    except Exception:
        pass
    
    return None


def get_timezone() -> str:
    """Get system timezone."""
    try:
        from datetime import timezone
        tz = datetime.now().astimezone().tzinfo
        tzname = tz.tzname(datetime.now()) if tz else 'Unknown'
        return tzname if tzname else 'Unknown'
    except Exception:
        return 'Unknown'


def collect_system_info() -> SystemInfo:
    """
    Collect all system information.
    
    Returns:
        SystemInfo object.
    """
    platform_info = get_platform_info()
    
    return SystemInfo(
        hostname=get_hostname(),
        fqdn=get_fqdn(),
        platform=platform_info['system'],
        platform_release=platform_info['release'],
        platform_version=platform_info['version'],
        architecture=platform_info['architecture'],
        processor=platform_info['processor'],
        cpu_count=os.cpu_count() or 1,
        total_memory_bytes=get_memory_info(),
        boot_time=get_boot_time(),
        username=get_username(),
        user_domain=os.environ.get('USERDOMAIN'),
        is_admin=is_running_as_admin(),
        system_root=os.environ.get('SystemRoot', 'C:\\Windows'),
        system_drive=os.environ.get('SystemDrive', 'C:'),
        collection_time=datetime.now().isoformat(),
        network_interfaces=get_network_interfaces(),
        disk_info=get_disk_info(),
        os_install_date=get_os_install_date(),
        timezone=get_timezone(),
        uptime_seconds=get_uptime_seconds(),
    )


def save_system_info(output_dir: str) -> str:
    """
    Collect and save system information.
    
    Args:
        output_dir: Output directory.
        
    Returns:
        Path to saved file.
    """
    system_info = collect_system_info()
    
    metadata_dir = os.path.join(output_dir, 'metadata')
    os.makedirs(metadata_dir, exist_ok=True)
    
    output_path = os.path.join(metadata_dir, 'system_info.json')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(asdict(system_info), f, indent=2, default=str)
    
    logger.info(f"Saved system info to {output_path}")
    return output_path


def get_system_info_dict() -> Dict:
    """
    Get system information as dictionary.
    
    Returns:
        Dictionary with system information.
    """
    system_info = collect_system_info()
    return asdict(system_info)
