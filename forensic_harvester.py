#!/usr/bin/env python3
"""
ForensicHarvester - Comprehensive Forensic Triage Tool

A Python-based forensic triage tool that operates in two modes:
1. Dead-box mode against a mounted dd image or raw image file
2. Live system mode on a running Windows machine

Collects forensic artifacts, organizes them into a structured folder hierarchy,
and produces a ZIP file with deterministic naming.
"""

import argparse
import os
import sys
import json
import logging
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the tool directory to path for imports
TOOL_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(TOOL_DIR))

# Import utilities
from utils.constants import (
    COLLECTION_LEVELS,
    CATEGORY_SHORTCUTS,
    LEVEL_CATEGORIES,
    DEFAULT_CONFIG,
)
from utils.system_info import collect_system_info, save_system_info
from utils.manifest import CollectionManifest
from utils.zip_utils import create_zip_file, generate_zip_filename
from utils.file_ops import ensure_directory
from utils.image_utils import DiskImage, is_image_file

# Import collectors using absolute imports
from collectors.base import BaseCollector, CollectionResult
from collectors.registry import RegistryCollector
from collectors.eventlogs import EventLogsCollector
from collectors.filesystem import FilesystemCollector
from collectors.execution import ExecutionCollector
from collectors.persistence import PersistenceCollector
from collectors.network import NetworkCollector
from collectors.usb_devices import USBDevicesCollector
from collectors.browser_chrome import BrowserChromeCollector
from collectors.browser_firefox import BrowserFirefoxCollector
from collectors.browser_edge import BrowserEdgeCollector
from collectors.browser_ie import BrowserIECollector
from collectors.email_outlook import EmailOutlookCollector
from collectors.email_thunderbird import EmailThunderbirdCollector
from collectors.email_other import EmailOtherCollector
from collectors.teams import TeamsCollector
from collectors.slack import SlackCollector
from collectors.discord import DiscordCollector
from collectors.signal import SignalCollector
from collectors.whatsapp import WhatsAppCollector
from collectors.telegram import TelegramCollector
from collectors.cloud_onedrive import CloudOneDriveCollector
from collectors.cloud_google_drive import CloudGoogleDriveCollector
from collectors.cloud_dropbox import CloudDropboxCollector
from collectors.cloud_other import CloudOtherCollector
from collectors.remote_access import RemoteAccessCollector
from collectors.rdp import RDPCollector
from collectors.ssh_ftp import SSHFTPCollector
from collectors.credentials import CredentialsCollector
from collectors.office import OfficeCollector
from collectors.antivirus import AntivirusCollector
from collectors.wer_crashes import WERCrashesCollector
from collectors.iis_web import IISWebCollector
from collectors.active_directory import ActiveDirectoryCollector
from collectors.database_clients import DatabaseClientsCollector
from collectors.dev_tools import DevToolsCollector
from collectors.password_managers import PasswordManagersCollector
from collectors.vpn import VPNCollector
from collectors.gaming import GamingCollector
from collectors.printing import PrintingCollector
from collectors.encryption import EncryptionCollector
from collectors.boot_uefi import BootUEFICollector
from collectors.etw_diagnostics import ETWDiagnosticsCollector
from collectors.windows_apps import WindowsAppsCollector
from collectors.wsl import WSLCollector
from collectors.virtualization import VirtualizationCollector
from collectors.recovery import RecoveryCollector
from collectors.logs import LogsCollector
from collectors.memory import MemoryCollector
from collectors.hashing import HashingCollector
from collectors.file_listing import FileListingCollector
from collectors.yara_scanner import YaraScannerCollector

# Collector class mapping
COLLECTOR_CLASSES = {
    'registry': RegistryCollector,
    'eventlogs': EventLogsCollector,
    'filesystem': FilesystemCollector,
    'execution': ExecutionCollector,
    'persistence': PersistenceCollector,
    'network': NetworkCollector,
    'usb_devices': USBDevicesCollector,
    'browser_chrome': BrowserChromeCollector,
    'browser_firefox': BrowserFirefoxCollector,
    'browser_edge': BrowserEdgeCollector,
    'browser_ie': BrowserIECollector,
    'email_outlook': EmailOutlookCollector,
    'email_thunderbird': EmailThunderbirdCollector,
    'email_other': EmailOtherCollector,
    'teams': TeamsCollector,
    'slack': SlackCollector,
    'discord': DiscordCollector,
    'signal': SignalCollector,
    'whatsapp': WhatsAppCollector,
    'telegram': TelegramCollector,
    'cloud_onedrive': CloudOneDriveCollector,
    'cloud_google_drive': CloudGoogleDriveCollector,
    'cloud_dropbox': CloudDropboxCollector,
    'cloud_other': CloudOtherCollector,
    'remote_access': RemoteAccessCollector,
    'rdp': RDPCollector,
    'ssh_ftp': SSHFTPCollector,
    'credentials': CredentialsCollector,
    'office': OfficeCollector,
    'antivirus': AntivirusCollector,
    'wer_crashes': WERCrashesCollector,
    'iis_web': IISWebCollector,
    'active_directory': ActiveDirectoryCollector,
    'database_clients': DatabaseClientsCollector,
    'dev_tools': DevToolsCollector,
    'password_managers': PasswordManagersCollector,
    'vpn': VPNCollector,
    'gaming': GamingCollector,
    'printing': PrintingCollector,
    'encryption': EncryptionCollector,
    'boot_uefi': BootUEFICollector,
    'etw_diagnostics': ETWDiagnosticsCollector,
    'windows_apps': WindowsAppsCollector,
    'wsl': WSLCollector,
    'virtualization': VirtualizationCollector,
    'recovery': RecoveryCollector,
    'logs': LogsCollector,
    'memory': MemoryCollector,
    'hashing': HashingCollector,
    'file_listing': FileListingCollector,
    'yara_scanner': YaraScannerCollector,
}


class ImageSourceRoot:
    """Wrapper for disk image as source root."""
    
    def __init__(self, image: DiskImage):
        self.image = image
    
    def __str__(self):
        return f"Image:{self.image.image_path}"


class ForensicHarvester:
    """Main forensic harvester class."""
    
    def __init__(self, config: Dict):
        """
        Initialize the harvester.
        
        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.level = config.get('level', 'complete')
        self.mode = config.get('mode', 'live')
        self.image_path = config.get('image_path')
        self.quiet = config.get('quiet', False)
        self.threads = config.get('threads', 1 if self.mode == 'image' else 4)
        
        # Determine source root
        self.image = None
        if self.mode == 'image' and self.image_path:
            if is_image_file(self.image_path):
                # Raw image file - open with pytsk3
                print(f"Opening disk image: {self.image_path}")
                try:
                    self.image = DiskImage(self.image_path)
                    self.source_root = ImageSourceRoot(self.image)
                    print(f"Image opened successfully")
                except Exception as e:
                    print(f"Error opening image: {e}")
                    print("Make sure pytsk3 is installed: pip install pytsk3")
                    sys.exit(1)
            else:
                # Mounted path
                self.source_root = self.image_path
        else:
            # Live mode - use system drive
            self.source_root = os.environ.get('SystemDrive', 'C:')
        
        # Generate output directory name
        if self.image_path:
            hostname = Path(self.image_path).stem
        else:
            hostname = os.environ.get('COMPUTERNAME', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.base_output_dir = f"ForensicHarvester_{hostname}_{timestamp}"
        
        output_base = config.get('output_dir', './output')
        self.output_root = os.path.join(output_base, self.base_output_dir)
        
        # Initialize manifest
        self.manifest = CollectionManifest(self.output_root, self.level)
        
        # Setup logging
        self._setup_logging()
        
        # Get categories to collect
        self.categories = self._get_categories()
        
        self.logger = logging.getLogger(__name__)
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = logging.DEBUG if not self.quiet else logging.WARNING
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Console handler
        if not self.quiet:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
        
        # File handler
        log_file = os.path.join(self.output_root, 'metadata', 'collection_log.txt')
        ensure_directory(os.path.dirname(log_file))
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    def _get_categories(self) -> List[str]:
        """
        Get list of categories to collect.
        
        Returns:
            List of category names.
        """
        categories = self.config.get('categories', [])
        
        if not categories:
            # Use level-based categories
            categories = LEVEL_CATEGORIES.get(self.level, [])
        else:
            # Expand shortcuts
            expanded = []
            for cat in categories:
                if cat in CATEGORY_SHORTCUTS:
                    expanded.extend(CATEGORY_SHORTCUTS[cat])
                else:
                    expanded.append(cat)
            categories = expanded
        
        return categories
    
    def run(self) -> bool:
        """
        Run the forensic collection.
        
        Returns:
            True if successful.
        """
        self.logger.info("=" * 80)
        self.logger.info("ForensicHarvester Starting")
        self.logger.info(f"Mode: {self.mode}")
        self.logger.info(f"Level: {self.level}")
        self.logger.info(f"Categories: {len(self.categories)}")
        self.logger.info(f"Source: {self.source_root}")
        self.logger.info(f"Output: {self.output_root}")
        self.logger.info("=" * 80)
        
        # Create output directory structure
        ensure_directory(self.output_root)
        
        # Save system info (if available)
        try:
            save_system_info(self.output_root)
        except Exception as e:
            self.logger.warning(f"Failed to collect system info: {e}")
        
        # Save config used
        config_path = os.path.join(self.output_root, 'metadata', 'config_used.yaml')
        with open(config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        
        # Run collectors
        self._run_collectors()
        
        # Save manifest
        self.manifest.save_manifest_json()
        self.manifest.save_manifest_csv()
        self.manifest.save_errors_log()
        
        # Create ZIP
        zip_path = self._create_zip()
        
        # Print summary
        self._print_summary(zip_path)
        
        # Close image if open
        if self.image:
            self.image.close()
        
        return True
    
    def _run_collectors(self):
        """Run all configured collectors."""
        self.logger.info(f"Running {len(self.categories)} collectors")
        
        # pytsk3 is not thread-safe, so run sequentially for image mode
        run_sequential = (self.mode == 'image')
        
        if run_sequential:
            # Run sequentially for image mode
            for category in self.categories:
                if category not in COLLECTOR_CLASSES:
                    self.logger.warning(f"Unknown category: {category}")
                    continue
                
                collector_class = COLLECTOR_CLASSES[category]
                
                try:
                    collector = collector_class(
                        config=self.config,
                        source_root='/' if self.mode == 'image' else str(self.source_root),
                        output_root=self.output_root,
                        level=self.level,
                        manifest=self.manifest,
                        image=self.image,
                    )
                    
                    if collector.should_collect():
                        result = collector.run()
                        self.logger.debug(f"{category}: {result.files_collected} files")
                except Exception as e:
                    self.logger.error(f"Failed to run {category} collector: {e}")
        else:
            # Use thread pool for parallel collection (live mode)
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                
                for category in self.categories:
                    if category not in COLLECTOR_CLASSES:
                        self.logger.warning(f"Unknown category: {category}")
                        continue
                    
                    collector_class = COLLECTOR_CLASSES[category]
                    
                    try:
                        collector = collector_class(
                            config=self.config,
                            source_root='/' if self.mode == 'image' else str(self.source_root),
                            output_root=self.output_root,
                            level=self.level,
                            manifest=self.manifest,
                            image=self.image,
                        )
                        
                        if collector.should_collect():
                            future = executor.submit(collector.run)
                            futures[future] = category
                    except Exception as e:
                        self.logger.error(f"Failed to initialize {category} collector: {e}")
                
                # Process results with progress bar
                if not self.quiet and futures:
                    try:
                        from tqdm import tqdm
                        with tqdm(total=len(futures), desc="Collecting") as pbar:
                            for future in as_completed(futures):
                                category = futures[future]
                                try:
                                    result = future.result()
                                    pbar.set_postfix_str(f"{category}: {result.files_collected} files")
                                except Exception as e:
                                    self.logger.error(f"Collector {category} failed: {e}")
                                pbar.update(1)
                    except ImportError:
                        # tqdm not available, run without progress bar
                        for future in as_completed(futures):
                            category = futures[future]
                            try:
                                result = future.result()
                            except Exception as e:
                                self.logger.error(f"Collector {category} failed: {e}")
                else:
                    # Quiet mode - just process results
                    for future in as_completed(futures):
                        category = futures[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            self.logger.error(f"Collector {category} failed: {e}")
    
    def _create_zip(self) -> Optional[str]:
        """
        Create ZIP archive of collected data.
        
        Returns:
            Path to ZIP file or None.
        """
        if not self.config.get('create_zip', True):
            return None
        
        self.logger.info("Creating ZIP archive")
        
        zip_filename = generate_zip_filename(
            hostname=os.environ.get('COMPUTERNAME', 'unknown') if self.mode == 'live' else 'image',
            timestamp=datetime.now(),
        )
        
        output_base = self.config.get('output_dir', './output')
        zip_path = os.path.join(output_base, zip_filename)
        
        password = self.config.get('zip_password')
        
        success = create_zip_file(
            source_dir=self.output_root,
            output_path=zip_path,
            password=password,
        )
        
        if success:
            self.logger.info(f"Created ZIP: {zip_path}")
            
            # Remove uncompressed directory if requested
            if not self.config.get('keep_unzipped', False):
                try:
                    import shutil
                    shutil.rmtree(self.output_root)
                    self.logger.info("Removed uncompressed directory")
                except Exception as e:
                    self.logger.warning(f"Failed to remove uncompressed directory: {e}")
            
            return zip_path
        else:
            self.logger.error("Failed to create ZIP")
            return None
    
    def _print_summary(self, zip_path: Optional[str]):
        """Print collection summary."""
        summary = self.manifest.get_summary()
        
        print("\n" + "=" * 80)
        print("COLLECTION SUMMARY")
        print("=" * 80)
        print(f"Total files:     {summary['total_files']}")
        print(f"Successful:      {summary['successful']}")
        print(f"Failed:          {summary['failed']}")
        print(f"Skipped:         {summary['skipped']}")
        print(f"Total size:      {summary['total_mb']:.2f} MB")
        print(f"Errors:          {summary['error_count']}")
        print(f"Warnings:        {summary['warning_count']}")
        
        if zip_path:
            print(f"\nZIP file:        {zip_path}")
        
        print("=" * 80)


def load_config(config_path: str) -> Dict:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file.
        
    Returns:
        Configuration dictionary.
    """
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f)
            return {**DEFAULT_CONFIG, **(file_config or {})}
    return DEFAULT_CONFIG.copy()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='ForensicHarvester - Comprehensive Forensic Triage Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live triage - small level
  python forensic_harvester.py --mode live --level small
  
  # Dead-box from raw dd image
  python forensic_harvester.py --mode image --image-path disk.dd --level complete
  
  # Dead-box from mounted image
  python forensic_harvester.py --mode image --image-path E:\\ --level complete
  
  # Exhaustive with YARA
  python forensic_harvester.py --mode image --image-path disk.dd --yara-rules ./rules/
        """
    )
    
    # Mode and image path
    parser.add_argument(
        '--mode',
        choices=['live', 'image'],
        default='live',
        help='Collection mode: live system or image file/mounted path (default: live)'
    )
    parser.add_argument(
        '--image-path',
        help='Path to disk image (.dd, .img, .E01) or mounted path'
    )
    
    # Collection level
    parser.add_argument(
        '--level',
        choices=COLLECTION_LEVELS,
        default='complete',
        help='Collection level (default: complete)'
    )
    
    # Categories
    parser.add_argument(
        '--categories',
        type=str,
        help='Comma-separated list of categories to collect'
    )
    
    # Users
    parser.add_argument(
        '--include-users',
        type=str,
        help='Comma-separated list of usernames to collect'
    )
    
    # Output
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./output',
        help='Output directory (default: ./output)'
    )
    
    # ZIP options
    parser.add_argument(
        '--zip-password',
        type=str,
        help='Password for ZIP encryption'
    )
    parser.add_argument(
        '--keep-unzipped',
        action='store_true',
        help='Keep uncompressed output directory'
    )
    parser.add_argument(
        '--no-zip',
        action='store_true',
        help='Skip ZIP creation'
    )
    
    # Performance
    parser.add_argument(
        '--threads',
        type=int,
        default=4,
        help='Number of parallel threads (default: 4)'
    )
    
    # YARA
    parser.add_argument(
        '--yara-rules',
        type=str,
        help='Path to YARA rules file or directory'
    )
    
    # Memory collection
    parser.add_argument(
        '--collect-pagefile',
        action='store_true',
        help='Collect pagefile.sys'
    )
    parser.add_argument(
        '--collect-hiberfil',
        action='store_true',
        help='Collect hiberfil.sys'
    )
    parser.add_argument(
        '--collect-swapfile',
        action='store_true',
        help='Collect swapfile.sys'
    )
    
    # Other options
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress stdout output'
    )
    parser.add_argument(
        '--max-file-size',
        type=int,
        default=0,
        help='Maximum file size in MB (0 = no limit)'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Load config from file
    config = load_config(args.config)
    
    # Override with CLI arguments
    config['mode'] = args.mode
    if args.image_path:
        config['mode'] = 'image'
        config['image_path'] = args.image_path
    if args.level:
        config['level'] = args.level
    if args.categories:
        config['categories'] = args.categories.split(',')
    if args.include_users:
        config['include_users'] = args.include_users.split(',')
    if args.output_dir:
        config['output_dir'] = args.output_dir
    if args.zip_password:
        config['zip_password'] = args.zip_password
    if args.keep_unzipped:
        config['keep_unzipped'] = True
    if args.no_zip:
        config['create_zip'] = False
    if args.threads:
        config['threads'] = args.threads
    if args.yara_rules:
        config['yara_rules'] = args.yara_rules
    if args.collect_pagefile:
        config['collect_pagefile'] = True
    if args.collect_hiberfil:
        config['collect_hiberfil'] = True
    if args.collect_swapfile:
        config['collect_swapfile'] = True
    if args.quiet:
        config['quiet'] = True
    if args.max_file_size:
        config['max_file_size_mb'] = args.max_file_size
    
    # Create and run harvester
    harvester = ForensicHarvester(config)
    
    try:
        success = harvester.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nCollection interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
