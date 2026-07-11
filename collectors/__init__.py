"""
Collectors package for Triager.

This package contains all artifact collectors organized by category.
"""

from collectors.base import BaseCollector, CollectionResult
from .registry import RegistryCollector
from .eventlogs import EventLogsCollector
from .filesystem import FilesystemCollector
from .execution import ExecutionCollector
from .persistence import PersistenceCollector
from .network import NetworkCollector
from .usb_devices import USBDevicesCollector
from .browser_chrome import BrowserChromeCollector
from .browser_firefox import BrowserFirefoxCollector
from .browser_edge import BrowserEdgeCollector
from .browser_ie import BrowserIECollector
from .email_outlook import EmailOutlookCollector
from .email_thunderbird import EmailThunderbirdCollector
from .email_other import EmailOtherCollector
from .teams import TeamsCollector
from .slack import SlackCollector
from .discord import DiscordCollector
from .signal import SignalCollector
from .whatsapp import WhatsAppCollector
from .telegram import TelegramCollector
from .cloud_onedrive import CloudOneDriveCollector
from .cloud_google_drive import CloudGoogleDriveCollector
from .cloud_dropbox import CloudDropboxCollector
from .cloud_other import CloudOtherCollector
from .remote_access import RemoteAccessCollector
from .rdp import RDPCollector
from .ssh_ftp import SSHFTPCollector
from .credentials import CredentialsCollector
from .office import OfficeCollector
from .antivirus import AntivirusCollector
from .wer_crashes import WERCrashesCollector
from .iis_web import IISWebCollector
from .active_directory import ActiveDirectoryCollector
from .database_clients import DatabaseClientsCollector
from .dev_tools import DevToolsCollector
from .password_managers import PasswordManagersCollector
from .vpn import VPNCollector
from .gaming import GamingCollector
from .printing import PrintingCollector
from .encryption import EncryptionCollector
from .boot_uefi import BootUEFICollector
from .etw_diagnostics import ETWDiagnosticsCollector
from .windows_apps import WindowsAppsCollector
from .wsl import WSLCollector
from .virtualization import VirtualizationCollector
from .recovery import RecoveryCollector
from .logs import LogsCollector
from .memory import MemoryCollector
from .hashing import HashingCollector
from .file_listing import FileListingCollector
from .yara_scanner import YaraScannerCollector

__all__ = [
    'BaseCollector',
    'CollectionResult',
    'RegistryCollector',
    'EventLogsCollector',
    'FilesystemCollector',
    'ExecutionCollector',
    'PersistenceCollector',
    'NetworkCollector',
    'USBDevicesCollector',
    'BrowserChromeCollector',
    'BrowserFirefoxCollector',
    'BrowserEdgeCollector',
    'BrowserIECollector',
    'EmailOutlookCollector',
    'EmailThunderbirdCollector',
    'EmailOtherCollector',
    'TeamsCollector',
    'SlackCollector',
    'DiscordCollector',
    'SignalCollector',
    'WhatsAppCollector',
    'TelegramCollector',
    'CloudOneDriveCollector',
    'CloudGoogleDriveCollector',
    'CloudDropboxCollector',
    'CloudOtherCollector',
    'RemoteAccessCollector',
    'RDPCollector',
    'SSHFTPCollector',
    'CredentialsCollector',
    'OfficeCollector',
    'AntivirusCollector',
    'WERCrashesCollector',
    'IISWebCollector',
    'ActiveDirectoryCollector',
    'DatabaseClientsCollector',
    'DevToolsCollector',
    'PasswordManagersCollector',
    'VPNCollector',
    'GamingCollector',
    'PrintingCollector',
    'EncryptionCollector',
    'BootUEFICollector',
    'ETWDiagnosticsCollector',
    'WindowsAppsCollector',
    'WSLCollector',
    'VirtualizationCollector',
    'RecoveryCollector',
    'LogsCollector',
    'MemoryCollector',
    'HashingCollector',
    'FileListingCollector',
    'YaraScannerCollector',
]
