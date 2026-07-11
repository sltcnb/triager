"""
Constants for Triager.

This module defines all path patterns, category mappings, and configuration constants
used throughout the application.
"""

from typing import Dict, List

# Collection level definitions
COLLECTION_LEVELS = ['small', 'complete', 'exhaustive']

# NOTE: the old CATEGORY_COLLECTOR_MAP (category -> class-name string) was
# removed in v1.2.0. Collector dispatch is now handled by auto-discovery in
# collectors/collector_registry.py — the single source of truth.

# Category shortcuts
CATEGORY_SHORTCUTS = {
    'browser_all': ['browser_chrome', 'browser_firefox', 'browser_edge', 'browser_ie'],
    'email_all': ['email_outlook', 'email_thunderbird', 'email_other'],
    'messaging_all': ['teams', 'slack', 'discord', 'signal', 'whatsapp', 'telegram'],
    'cloud_all': ['cloud_onedrive', 'cloud_google_drive', 'cloud_dropbox', 'cloud_other'],
}

# Categories per level
LEVEL_CATEGORIES: Dict[str, List[str]] = {
    'small': [
        'registry',
        'eventlogs',
        'filesystem',
        'execution',
        'persistence',
        'network',
        'usb_devices',
        'credentials',
        'antivirus',
        'wer_crashes',
        'logs',
    ],
    'complete': [
        'registry',
        'eventlogs',
        'filesystem',
        'execution',
        'persistence',
        'network',
        'usb_devices',
        'browser_chrome',
        'browser_firefox',
        'browser_edge',
        'browser_ie',
        'email_outlook',
        'email_thunderbird',
        'email_other',
        'teams',
        'slack',
        'discord',
        'signal',
        'whatsapp',
        'telegram',
        'cloud_onedrive',
        'cloud_google_drive',
        'cloud_dropbox',
        'cloud_other',
        'remote_access',
        'rdp',
        'ssh_ftp',
        'credentials',
        'office',
        'antivirus',
        'wer_crashes',
        'iis_web',
        'active_directory',
        'database_clients',
        'dev_tools',
        'password_managers',
        'vpn',
        'gaming',
        'printing',
        'encryption',
        'boot_uefi',
        'etw_diagnostics',
        'windows_apps',
        'wsl',
        'virtualization',
        'recovery',
        'logs',
        'memory',
    ],
    'exhaustive': [
        'registry',
        'eventlogs',
        'filesystem',
        'execution',
        'persistence',
        'network',
        'usb_devices',
        'browser_chrome',
        'browser_firefox',
        'browser_edge',
        'browser_ie',
        'email_outlook',
        'email_thunderbird',
        'email_other',
        'teams',
        'slack',
        'discord',
        'signal',
        'whatsapp',
        'telegram',
        'cloud_onedrive',
        'cloud_google_drive',
        'cloud_dropbox',
        'cloud_other',
        'remote_access',
        'rdp',
        'ssh_ftp',
        'credentials',
        'office',
        'antivirus',
        'wer_crashes',
        'iis_web',
        'active_directory',
        'database_clients',
        'dev_tools',
        'password_managers',
        'vpn',
        'gaming',
        'printing',
        'encryption',
        'boot_uefi',
        'etw_diagnostics',
        'windows_apps',
        'wsl',
        'virtualization',
        'recovery',
        'logs',
        'memory',
        'hashing',
        'file_listing',
        'yara_scanner',
    ],
}

# Windows system paths
WINDOWS_PATHS = {
    'system_root': '%SYSTEMROOT%',
    'system32': '%SYSTEMROOT%\\System32',
    'syswow64': '%SYSTEMROOT%\\SysWOW64',
    'temp': '%TEMP%',
    'program_data': '%PROGRAMDATA%',
    'program_files': '%PROGRAMFILES%',
    'program_files_x86': '%PROGRAMFILES(X86)%',
}

# Registry hive paths (relative to system root)
REGISTRY_HIVES = {
    'SYSTEM': 'System32\\config\\SYSTEM',
    'SOFTWARE': 'System32\\config\\SOFTWARE',
    'SAM': 'System32\\config\\SAM',
    'SECURITY': 'System32\\config\\SECURITY',
    'DEFAULT': 'System32\\config\\DEFAULT',
    'COMPONENTS': 'System32\\config\\COMPONENTS',
    'BCD': 'System32\\config\\BCD',
    'ELAM': 'System32\\config\\ELAM',
    'DRIVERS': 'System32\\config\\DRIVERS',
    'BBI': 'System32\\config\\BBI',
    'AMCACHE': 'System32\\Amcache.hve',
}

# User profile registry hives
USER_REGISTRY_HIVES = [
    'NTUSER.DAT',
    'NTUSER.DAT.LOG1',
    'NTUSER.DAT.LOG2',
    'UsrClass.dat',
    'UsrClass.dat.LOG1',
    'UsrClass.dat.LOG2',
]

# Critical event logs for small level
CRITICAL_EVENT_LOGS = [
    'Security.evtx',
    'System.evtx',
    'Application.evtx',
    'Microsoft-Windows-PowerShell/Operational.evtx',
    'Microsoft-Windows-Sysmon/Operational.evtx',
    'Microsoft-Windows-TaskScheduler/Operational.evtx',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx',
    'Microsoft-Windows-Windows Defender/Operational.evtx',
    'Microsoft-Windows-Bits-Client/Operational.evtx',
    'Microsoft-Windows-WMI-Activity/Operational.evtx',
    'Microsoft-Windows-WinRM/Operational.evtx',
]

# Prefetch directory
PREFETCH_DIR = 'Windows\\Prefetch'

# Superfetch directory
SUPERFETCH_DIR = 'Windows\\Prefetch'

# Common browser paths
BROWSER_PATHS = {
    'chrome': {
        'base': 'AppData\\Local\\Google\\Chrome\\User Data',
        'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)],
    },
    'edge': {
        'base': 'AppData\\Local\\Microsoft\\Edge\\User Data',
        'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)],
    },
    'firefox': {
        'base': 'AppData\\Roaming\\Mozilla\\Firefox\\Profiles',
        'profiles': None,  # Dynamic discovery
    },
}

# Common file extensions for different categories
FILE_EXTENSIONS = {
    'registry': ['.dat', '.hive', '.hve'],
    'eventlogs': ['.evtx'],
    'prefetch': ['.pf'],
    'superfetch': ['.db'],
    'office_docs': ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pst', '.ost'],
    'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
    'executables': ['.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv'],
    'scripts': ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf'],
    'config': ['.xml', '.json', '.ini', '.cfg', '.conf', '.yaml', '.yml'],
    'logs': ['.log', '.etl', '.txt'],
    'database': ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb'],
}

# PE file extensions for YARA scanning
PE_EXTENSIONS = ['.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.efi']

# NTFS metadata files
NTFS_METADATA_FILES = [
    '$MFT',
    '$MFTMirr',
    '$LogFile',
    '$Volume',
    '$AttrDef',
    '$Bitmap',
    '$Boot',
    '$BadClus',
    '$Secure',
    '$UpCase',
    '$Extend',
]

# Antivirus vendor directories
ANTIVENDOR_DIRS = {
    'defender': 'Windows Defender',
    'symantec': 'Symantec\\Symantec Endpoint Protection',
    'mcafee': 'McAfee',
    'crowdstrike': 'CrowdStrike',
    'sentinelone': 'SentinelOne',
    'carbon_black': 'Carbon Black',
    'sophos': 'Sophos',
    'trend_micro': 'Trend Micro',
    'eset': 'ESET',
    'kaspersky': 'Kaspersky Lab',
    'bitdefender': 'Bitdefender',
    'malwarebytes': 'Malwarebytes',
    'webroot': 'Webroot',
    'avast': 'Avast',
    'avg': 'AVG',
    'f_secure': 'F-Secure',
    'panda': 'Panda Security',
    'cylance': 'Cylance',
    'hitman_pro': 'HitmanPro',
}

# Remote access tool paths
REMOTE_ACCESS_PATHS = {
    'anydesk': 'AnyDesk',
    'teamviewer': 'TeamViewer',
    'screenconnect': 'ScreenConnect',
    'logmein': 'LogMeIn',
    'splashtop': 'Splashtop',
    'remote_pc': 'RemotePC',
    'rustdesk': 'RustDesk',
}

# Cloud storage paths
CLOUD_PATHS = {
    'onedrive': 'Microsoft\\OneDrive',
    'google_drive': 'Google\\Drive',
    'dropbox': 'Dropbox',
    'box': 'Box',
    'icloud': 'Apple Computer\\MobileSync',
    'mega': 'MEGA',
}

# VPN paths
VPN_PATHS = {
    'openvpn': 'OpenVPN',
    'wireguard': 'WireGuard',
    'cisco_anyconnect': 'Cisco\\Cisco AnyConnect Secure Mobility Client',
    'globalprotect': 'Palo Alto Networks\\GlobalProtect',
    'forticlient': 'Fortinet\\FortiClient',
    'nordvpn': 'NordVPN',
    'expressvpn': 'ExpressVPN',
    'protonvpn': 'ProtonVPN',
}

# Gaming paths
GAMING_PATHS = {
    'steam': 'Steam',
    'epic': 'Epic Games',
    'gog': 'GOG.com',
    'battle_net': 'Battle.net',
    'ubisoft': 'Ubisoft Game Launcher',
    'ea': 'Electronic Arts',
    'xbox': 'Microsoft\\Xbox',
}

# Development tools paths
DEV_TOOLS_PATHS = {
    'git': ['.gitconfig', '.git-credentials'],
    'vscode': 'Code',
    'visual_studio': 'Microsoft\\VisualStudio',
    'jetbrains': 'JetBrains',
    'notepadpp': 'Notepad++',
    'sublime': 'Sublime Text',
    'docker': 'Docker',
    'kubernetes': '.kube',
    'aws': '.aws',
    'azure': '.azure',
    'gcp': '.config\\gcloud',
}

# Password manager paths
PASSWORD_MANAGER_PATHS = {
    'keepass': ['KeePass', '.kdbx'],
    '1password': '1Password',
    'lastpass': 'LastPass',
    'bitwarden': 'Bitwarden',
    'dashlane': 'Dashlane',
    'robform': 'RoboForm',
    'enpass': 'Enpass',
    'nordpass': 'NordPass',
    'keeper': 'Keeper',
}

# Output directory structure
OUTPUT_STRUCTURE = {
    'metadata': ['collection_manifest.json', 'collection_log.txt', 'system_info.json', 
                 'config_used.yaml', 'errors.log'],
    'registry': ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'COMPONENTS', 
                 'BCD', 'ELAM', 'DRIVERS', 'BBI', 'AMCACHE', 'users'],
    'eventlogs': [],
    'filesystem': ['$MFT', '$LogFile', '$UsnJrnl_$J', '$Boot', '$Secure_$SDS', 
                   'ads_inventory.csv', 'sdb_files'],
    'execution': ['prefetch', 'superfetch', 'srum', 'amcache', 'timeline', 'pca'],
    'persistence': ['scheduled_tasks', 'wmi_repository', 'startup_folders', 
                    'autoruns_registry_export.json'],
    'network': ['hosts', 'wlan_profiles', 'firewall_log', 'vpn', 'bits'],
    'usb_devices': ['setupapi.dev.log', 'setupapi.setup.log', 'device_inventory.json'],
    'browser': ['chrome', 'firefox', 'edge', 'ie'],
    'email': ['outlook', 'thunderbird', 'other'],
    'messaging': ['teams', 'slack', 'discord', 'signal', 'whatsapp', 'telegram'],
    'cloud': ['onedrive', 'google_drive', 'dropbox', 'other'],
    'remote_access': ['anydesk', 'teamviewer', 'screenconnect', 'vnc', 'other'],
    'rdp': ['bitmap_cache', 'rdp_files', 'mstsc_prefetch'],
    'ssh_ftp': ['ssh', 'putty', 'winscp', 'filezilla', 'other'],
    'credentials': ['sam', 'lsa', 'dpapi', 'credential_manager', 'ngc', 'certificates'],
    'office': ['mru_export.json', 'trust_records_export.json', 'addins', 
               'vba_projects', 'onenote_cache'],
    'antivirus': ['defender'],
    'wer_crashes': ['report_queue', 'report_archive', 'minidumps', 'MEMORY.DMP', 
                    'live_kernel_reports'],
    'iis_web': ['iis_logs', 'applicationHost.config', 'web_configs', 'freb', 
                'httperr', 'apache', 'nginx'],
    'active_directory': ['ntds.dit', 'ntds_logs', 'sysvol', 'netlogon', 'adcs'],
    'database_clients': ['ssms', 'dbeaver', 'other'],
    'dev_tools': ['git', 'vscode', 'visual_studio', 'jetbrains', 'notepadpp', 
                  'docker', 'cloud_cli', 'powershell_profiles', 'terminal'],
    'password_managers': ['keepass', '1password', 'bitwarden', 'other'],
    'vpn': ['openvpn', 'wireguard', 'cisco_anyconnect', 'other'],
    'gaming': ['steam', 'epic', 'other'],
    'printing': ['spool_files', 'printer_history.json'],
    'encryption': ['bitlocker', 'veracrypt', 'efs'],
    'boot_uefi': ['bcd', 'efi', 'measured_boot', 'bootstat.dat', 'NTBOOTLOG.txt', 
                  'SrtTrail.txt', 'ReAgent.xml'],
    'etw_diagnostics': ['autologger', 'sleepstudy', 'diagtrack', 'perfmon'],
    'windows_apps': ['sticky_notes', 'cortana', 'recall', 'photos', 'clipboard', 
                     'notifications', 'phone_link', 'media_player', 'calendar_people'],
    'wsl': [],
    'virtualization': ['hyperv', 'docker', 'vhd_vhdx_inventory.csv', 
                       'iso_img_inventory.csv', 'sandbox', 'wdag'],
    'recovery': ['vss', 'windows_old', 'file_history', 'system_restore'],
    'logs': ['cbs', 'dism', 'windows_update', 'setup', 'panther', 'sfc', 'msi', 'msrt'],
    'memory': ['pagefile.sys', 'hiberfil.sys', 'swapfile.sys'],
    'hashing': ['collected_files_hashes.csv', 'system_executables_hashes.csv'],
    'file_listing': ['full_volume_listing.csv'],
    'yara': ['yara_hits.json', 'entropy_analysis.csv'],
}

# Default configuration
DEFAULT_CONFIG = {
    'mode': 'live',
    'image_path': None,
    'level': 'complete',
    'categories': [],
    'output_dir': './output',
    'threads': 4,
    'zip_password': None,
    'keep_unzipped': False,
    'quiet': False,
    'hash_collected': True,
    'hash_system_executables': False,
    'yara_rules': None,
    'collect_pagefile': False,
    'collect_hiberfil': False,
    'collect_swapfile': False,
    'collect_memory_dump': False,
    'collect_vss': False,
    'max_file_size_mb': 0,  # 0 = no limit
    'exclude_patterns': [],
    'include_users': [],
    'custom_paths': [],
}

# Privilege constants for Windows
SE_BACKUP_PRIVILEGE = 'SeBackupPrivilege'
SE_SECURITY_PRIVILEGE = 'SeSecurityPrivilege'
SE_RESTORE_PRIVILEGE = 'SeRestorePrivilege'

# NTFS stream names
ADS_ZONE_IDENTIFIER = 'Zone.Identifier'
ADS_SUMMARY_INFORMATION = ':$INDEX_ALLOCATION'

# File attributes
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04
FILE_ATTRIBUTE_ARCHIVE = 0x20

# Maximum path length for Windows (with \\?\ prefix support)
MAX_PATH_WINDOWS = 32767

# Default chunk size for file operations (64KB)
DEFAULT_CHUNK_SIZE = 65536

# Hash algorithms
HASH_ALGORITHMS = ['md5', 'sha256']
