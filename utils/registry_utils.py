"""
Registry utilities for Triager.

This module provides registry access and parsing functionality for both
live systems and offline hives.
"""

import os
import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from utils.constants import REGISTRY_HIVES, USER_REGISTRY_HIVES
from utils.file_ops import extend_path, copy_file_with_metadata

logger = logging.getLogger(__name__)

# Try to import registry parsing library
try:
    from Registry import Registry
    REGISTRY_LIB_AVAILABLE = True
except ImportError:
    REGISTRY_LIB_AVAILABLE = False
    logger.debug("python-registry not available, offline parsing disabled")

# Try to import winreg for live registry access
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    logger.debug("winreg not available (non-Windows)")


@dataclass
class RegistryValue:
    """Represents a registry value."""
    path: str
    name: str
    value: Any
    value_type: str
    timestamp: Optional[str] = None


@dataclass
class RegistryKey:
    """Represents a registry key with its values."""
    path: str
    name: str
    values: List[RegistryValue]
    subkeys: List['RegistryKey']
    last_write_time: Optional[str] = None


class RegistryParser:
    """Parser for offline registry hives."""
    
    def __init__(self, hive_path: str):
        """
        Initialize the registry parser.
        
        Args:
            hive_path: Path to the registry hive file.
        """
        self.hive_path = extend_path(hive_path)
        self.registry = None
        self.root_key = None
        
        if not REGISTRY_LIB_AVAILABLE:
            logger.warning(f"Cannot parse {hive_path}: python-registry not available")
            return
        
        try:
            self.registry = Registry(self.hive_path)
            self.root_key = self.registry.root()
        except Exception as e:
            logger.warning(f"Failed to open registry hive {hive_path}: {e}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.registry:
            try:
                self.registry.close()
            except Exception:
                pass
    
    def get_key(self, path: str) -> Optional[Any]:
        """
        Get a registry key by path.
        
        Args:
            path: Path to the key (e.g., "Software\\Microsoft").
            
        Returns:
            Registry key object or None.
        """
        if not self.registry:
            return None
        
        try:
            return self.registry.open_key(path)
        except Exception:
            return None
    
    def get_value(self, key_path: str, value_name: str) -> Optional[Any]:
        """
        Get a registry value.
        
        Args:
            key_path: Path to the key.
            value_name: Name of the value.
            
        Returns:
            Value or None.
        """
        key = self.get_key(key_path)
        if not key:
            return None
        
        try:
            return key.value(value_name).value()
        except Exception:
            return None
    
    def enumerate_keys(self, path: str = '') -> List[str]:
        """
        Enumerate all subkeys at a path.
        
        Args:
            path: Path to enumerate.
            
        Returns:
            List of subkey paths.
        """
        if not self.registry:
            return []
        
        try:
            key = self.registry.open_key(path) if path else self.root_key
            if not key:
                return []
            
            subkeys = []
            for subkey in key.subkeys():
                subkeys.append(subkey.path())
            
            return subkeys
        except Exception as e:
            logger.debug(f"Error enumerating keys at {path}: {e}")
            return []
    
    def enumerate_values(self, path: str) -> List[RegistryValue]:
        """
        Enumerate all values in a key.
        
        Args:
            path: Path to the key.
            
        Returns:
            List of RegistryValue objects.
        """
        if not self.registry:
            return []
        
        try:
            key = self.registry.open_key(path)
            if not key:
                return []
            
            values = []
            for value in key.values():
                value_type = self._get_value_type_name(value.value_type())
                values.append(RegistryValue(
                    path=path,
                    name=value.name() or '(Default)',
                    value=value.value(),
                    value_type=value_type,
                ))
            
            return values
        except Exception as e:
            logger.debug(f"Error enumerating values at {path}: {e}")
            return []
    
    def _get_value_type_name(self, value_type: int) -> str:
        """Convert registry value type to string name."""
        type_names = {
            0: 'REG_NONE',
            1: 'REG_SZ',
            2: 'REG_EXPAND_SZ',
            3: 'REG_BINARY',
            4: 'REG_DWORD',
            5: 'REG_DWORD_BE',
            6: 'REG_LINK',
            7: 'REG_MULTI_SZ',
            8: 'REG_RESOURCE_LIST',
            9: 'REG_FULL_RESOURCE_DESCRIPTOR',
            10: 'REG_RESOURCE_REQUIREMENTS_LIST',
            11: 'REG_QWORD',
        }
        return type_names.get(value_type, f'UNKNOWN({value_type})')
    
    def export_key_to_dict(self, path: str, recursive: bool = True) -> Optional[Dict]:
        """
        Export a registry key and its contents to a dictionary.
        
        Args:
            path: Path to the key.
            recursive: Whether to include subkeys recursively.
            
        Returns:
            Dictionary with key data or None.
        """
        if not self.registry:
            return None
        
        try:
            key = self.registry.open_key(path)
            if not key:
                return None
            
            result = {
                'path': path,
                'name': key.name(),
                'values': [],
                'subkeys': [],
            }
            
            # Get last write time
            try:
                timestamp = datetime.fromtimestamp(key.timestamp())
                result['last_write_time'] = timestamp.isoformat()
            except Exception:
                pass
            
            # Get values
            for value in key.values():
                try:
                    result['values'].append({
                        'name': value.name() or '(Default)',
                        'type': self._get_value_type_name(value.value_type()),
                        'value': self._serialize_value(value.value()),
                    })
                except Exception:
                    pass
            
            # Get subkeys recursively
            if recursive:
                for subkey in key.subkeys():
                    subkey_data = self.export_key_to_dict(subkey.path(), recursive=True)
                    if subkey_data:
                        result['subkeys'].append(subkey_data)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error exporting key {path}: {e}")
            return None
    
    def _serialize_value(self, value: Any) -> Any:
        """Serialize a registry value for JSON export."""
        if isinstance(value, bytes):
            return value.hex()
        elif isinstance(value, list):
            return [self._serialize_value(v) for v in value]
        else:
            return value


class LiveRegistryAccess:
    """Access to the live Windows registry."""
    
    def __init__(self):
        """Initialize live registry access."""
        if not WINREG_AVAILABLE:
            logger.warning("winreg not available for live registry access")
    
    def get_value(self, hive: str, path: str, value_name: str) -> Optional[Any]:
        """
        Get a registry value from the live registry.
        
        Args:
            hive: Registry hive name (e.g., 'HKEY_LOCAL_MACHINE').
            path: Key path.
            value_name: Value name.
            
        Returns:
            Value or None.
        """
        if not WINREG_AVAILABLE:
            return None
        
        try:
            hive_map = {
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKEY_USERS': winreg.HKEY_USERS,
                'HKU': winreg.HKEY_USERS,
                'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
                'HKCC': winreg.HKEY_CURRENT_CONFIG,
            }
            
            hive_key = hive_map.get(hive.upper())
            if not hive_key:
                logger.warning(f"Unknown hive: {hive}")
                return None
            
            key = winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ)
            try:
                value, value_type = winreg.QueryValueEx(key, value_name)
                return value
            finally:
                winreg.CloseKey(key)
                
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"Error reading registry: {e}")
            return None
    
    def enumerate_keys(self, hive: str, path: str) -> List[str]:
        """
        Enumerate subkeys in the live registry.
        
        Args:
            hive: Registry hive name.
            path: Key path.
            
        Returns:
            List of subkey names.
        """
        if not WINREG_AVAILABLE:
            return []
        
        try:
            hive_map = {
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_USERS': winreg.HKEY_USERS,
                'HKU': winreg.HKEY_USERS,
            }
            
            hive_key = hive_map.get(hive.upper())
            if not hive_key:
                return []
            
            key = winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ)
            try:
                subkeys = []
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkeys.append(winreg.EnumKey(key, i))
                return subkeys
            finally:
                winreg.CloseKey(key)
                
        except Exception as e:
            logger.debug(f"Error enumerating registry keys: {e}")
            return []
    
    def enumerate_values(self, hive: str, path: str) -> List[Dict]:
        """
        Enumerate values in a registry key.
        
        Args:
            hive: Registry hive name.
            path: Key path.
            
        Returns:
            List of dictionaries with value information.
        """
        if not WINREG_AVAILABLE:
            return []
        
        try:
            hive_map = {
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_USERS': winreg.HKEY_USERS,
                'HKU': winreg.HKEY_USERS,
            }
            
            hive_key = hive_map.get(hive.upper())
            if not hive_key:
                return []
            
            key = winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ)
            try:
                values = []
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, value_type = winreg.EnumValue(key, i)
                    values.append({
                        'name': name,
                        'value': value,
                        'type': value_type,
                    })
                return values
            finally:
                winreg.CloseKey(key)
                
        except Exception as e:
            logger.debug(f"Error enumerating registry values: {e}")
            return []


def collect_registry_hives(
    system_root: str,
    output_root: str,
    users: List[str] = None,
) -> List[Dict]:
    """
    Collect all registry hives from a system.
    
    Args:
        system_root: System root directory.
        output_root: Output directory for collected files.
        users: List of usernames to collect hives for.
        
    Returns:
        List of collection results.
    """
    results = []
    
    # Collect system hives
    for hive_name, relative_path in REGISTRY_HIVES.items():
        src_path = os.path.join(system_root, relative_path)
        dst_path = os.path.join(output_root, 'registry', hive_name)
        
        if os.path.exists(src_path):
            success, error = copy_file_with_metadata(src_path, dst_path)
            results.append({
                'hive': hive_name,
                'source': src_path,
                'destination': dst_path,
                'success': success,
                'error': error,
            })
            
            # Also collect transaction logs
            for log_ext in ['.LOG1', '.LOG2']:
                log_path = src_path + log_ext
                if os.path.exists(log_path):
                    log_dst = dst_path + log_ext
                    success, error = copy_file_with_metadata(log_path, log_dst)
                    results.append({
                        'hive': hive_name + log_ext,
                        'source': log_path,
                        'destination': log_dst,
                        'success': success,
                        'error': error,
                    })
    
    # Collect user hives if users specified
    if users:
        for username in users:
            user_profile = os.path.join(
                os.environ.get('SystemDrive', 'C:'),
                'Users',
                username
            )
            
            for hive_name in USER_REGISTRY_HIVES:
                src_path = os.path.join(user_profile, hive_name)
                dst_dir = os.path.join(output_root, 'registry', 'users', username)
                dst_path = os.path.join(dst_dir, hive_name)
                
                if os.path.exists(src_path):
                    os.makedirs(dst_dir, exist_ok=True)
                    success, error = copy_file_with_metadata(src_path, dst_path)
                    results.append({
                        'hive': f"{username}\\{hive_name}",
                        'source': src_path,
                        'destination': dst_path,
                        'success': success,
                        'error': error,
                    })
    
    return results


def export_autoruns_to_json(
    registry_root: str,
    output_path: str,
) -> Dict:
    """
    Export all autorun/persistence registry keys to JSON.
    
    Args:
        registry_root: Path to extracted registry hives.
        output_path: Path for output JSON file.
        
    Returns:
        Dictionary with all autorun data.
    """
    autoruns = {
        'run_keys': [],
        'services': [],
        'scheduled_tasks': [],
        'startup_folders': [],
        'asep': {},
    }
    
    # Try to parse SYSTEM hive for services
    system_hive = os.path.join(registry_root, 'SYSTEM')
    if os.path.exists(system_hive) and REGISTRY_LIB_AVAILABLE:
        with RegistryParser(system_hive) as parser:
            # Enumerate services
            services_key = parser.get_key('ControlSet001\\services')
            if services_key:
                for subkey in services_key.subkeys():
                    try:
                        service_data = {
                            'name': subkey.name(),
                            'display_name': None,
                            'image_path': None,
                            'start_type': None,
                            'service_dll': None,
                        }
                        
                        try:
                            service_data['display_name'] = subkey.value('DisplayName').value()
                        except Exception:
                            pass
                        
                        try:
                            service_data['image_path'] = subkey.value('ImagePath').value()
                        except Exception:
                            pass
                        
                        try:
                            service_data['start_type'] = subkey.value('Start').value()
                        except Exception:
                            pass
                        
                        # Check for ServiceDll
                        params = subkey.subkey('Parameters')
                        if params:
                            try:
                                service_data['service_dll'] = params.value('ServiceDll').value()
                            except Exception:
                                pass
                        
                        autoruns['services'].append(service_data)
                    except Exception:
                        pass
    
    # Try to parse SOFTWARE hive
    software_hive = os.path.join(registry_root, 'SOFTWARE')
    if os.path.exists(software_hive) and REGISTRY_LIB_AVAILABLE:
        with RegistryParser(software_hive) as parser:
            # Microsoft\\Windows\\CurrentVersion\\Run
            run_paths = [
                'Microsoft\\Windows\\CurrentVersion\\Run',
                'Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'Microsoft\\Windows\\CurrentVersion\\RunOnceEx',
                'Microsoft\\Windows\\CurrentVersion\\RunServices',
            ]
            
            for run_path in run_paths:
                key = parser.get_key(run_path)
                if key:
                    for value in key.values():
                        autoruns['run_keys'].append({
                            'path': run_path,
                            'name': value.name(),
                            'value': value.value(),
                            'hive': 'SOFTWARE',
                        })
    
    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(autoruns, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to write autoruns JSON: {e}")
    
    return autoruns
