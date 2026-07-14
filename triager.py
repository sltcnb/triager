#!/usr/bin/env python3
"""
Triager - Comprehensive Forensic Triage Tool

A Python-based forensic triage tool that operates in two modes:
1. Dead-box mode against a mounted dd image or raw image file
2. Live system mode on a running Windows machine

Collects forensic artifacts, organizes them into a structured folder hierarchy,
and produces a ZIP file with deterministic naming.
"""

import argparse
import os
import sys
import logging
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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
from utils.system_info import save_system_info
from utils.manifest import CollectionManifest
from utils.zip_utils import create_zip_file, generate_zip_filename
from utils.file_ops import ensure_directory
from utils.image_utils import DiskImage, is_image_file

# Collector dispatch is now handled by the auto-discovery registry + the
# HarvesterCollection orchestrator (single source of truth — no static maps).
from collectors import collector_registry as registry
from collectors.orchestrator import HarvesterCollection
from sources import build_source

class ImageSourceRoot:
    """Wrapper for disk image as source root."""

    def __init__(self, image: DiskImage):
        self.image = image

    def __str__(self):
        return f"Image:{self.image.image_path}"


class Triager:
    """Main Triager class."""

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
        self.mount_path = config.get('path')
        self.disk = config.get('disk')
        self.bitlocker_key = config.get('bitlocker_key', '')
        self.output_format = config.get('output_format', 'zip')
        self.dry_run = config.get('dry_run', False)
        self.quiet = config.get('quiet', False)
        self.threads = config.get('threads', 4)
        self.session_result = None
        self.last_zip = None
        self.exit_code = 0

        # Build the unified artifact source (live / image / mount / raw device).
        self.image = None
        if self.disk:
            # Raw block device (+ optional BitLocker); mounted in run().
            self.source = build_source(disk=self.disk, bitlocker_key=self.bitlocker_key)
            self.source_root = self.disk
            self.threads = 1
        elif self.mount_path:
            self.source = build_source(mount_path=self.mount_path)
            self.source_root = self.mount_path
        elif self.mode == 'image' and self.image_path:
            if is_image_file(self.image_path):
                print(f"Opening disk image: {self.image_path}")
                try:
                    self.image = DiskImage(self.image_path)
                except Exception as e:
                    print(f"Error opening image: {e}")
                    print("Make sure pytsk3 is installed: pip install pytsk3")
                    sys.exit(1)
                self.source = build_source(image=self.image)
                self.source_root = '/'
                self.threads = 1
            else:
                # A directory that was passed via --image-path == mounted volume.
                self.source = build_source(mount_path=self.image_path)
                self.source_root = self.image_path
        else:
            # Live mode - use system drive.
            self.source_root = os.environ.get('SystemDrive', 'C:') if os.name == 'nt' else '/'
            self.source = build_source(self.source_root)

        # Target OS drives default category selection. Dead-box sources are
        # assumed Windows (NTFS) unless overridden; live uses the host OS.
        self.dead_box = bool(self.disk or self.mount_path or self.image or
                             (self.mode == 'image'))
        if config.get('target_os'):
            self.target_os = config['target_os']
        elif self.dead_box:
            self.target_os = 'windows'
        else:
            self.target_os = {'nt': 'windows', 'posix': 'linux'}.get(os.name, 'linux')
            if sys.platform == 'darwin':
                self.target_os = 'macos'

        # Generate output directory name
        if self.image_path:
            hostname = Path(self.image_path).stem
        else:
            hostname = os.environ.get('COMPUTERNAME', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.base_output_dir = f"Triager_{hostname}_{timestamp}"

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
            if self.target_os == 'windows':
                # Preserve existing level semantics for Windows.
                categories = list(LEVEL_CATEGORIES.get(self.level, []))
            else:
                # OS default = full catalog for the target OS, minus heavy opt-in.
                from utils import capabilities as caps
                heavy = {'memory', 'hashing', 'file_listing', 'yara', 'file_search'}
                categories = sorted(caps.category_keys(self.target_os) - heavy)
        else:
            # Expand shortcuts
            expanded = []
            for cat in categories:
                if cat in CATEGORY_SHORTCUTS:
                    expanded.extend(CATEGORY_SHORTCUTS[cat])
                else:
                    expanded.append(cat)
            categories = expanded

        # Dead-box: optionally drop categories that don't work over a mount.
        if self.config.get('skip_problematic') and self.dead_box:
            problematic = {'memory', 'filesystem'}  # raw-volume / live-only artifacts
            categories = [c for c in categories if c not in problematic]

        return categories

    def run(self) -> bool:
        """
        Run the forensic collection.
        
        Returns:
            True if successful.
        """
        self.logger.info("=" * 80)
        self.logger.info("Triager Starting")
        self.logger.info(f"Mode: {self.mode}")
        self.logger.info(f"Level: {self.level}")
        self.logger.info(f"Categories: {len(self.categories)}")
        self.logger.info(f"Source: {self.source_root}")
        self.logger.info(f"Output: {self.output_root}")
        self.logger.info("=" * 80)

        # Dry-run: list what would be collected, collect nothing.
        if self.dry_run:
            print("DRY RUN — categories that would be collected:")
            for cat in self.categories:
                cls = registry.get(cat)
                mark = cls.__name__ if cls else "UNKNOWN"
                print(f"  {cat:24s} -> {mark}")
            return True

        # Prepare the source (mount/unlock a raw device if needed).
        try:
            self.source.open()
        except Exception as e:
            self.logger.error(f"Failed to open source: {e}")
            self.exit_code = 1
            return False

        # Create output directory structure
        ensure_directory(self.output_root)

        # Save system info (if available)
        try:
            save_system_info(self.output_root)
        except Exception as e:
            self.logger.warning(f"Failed to collect system info: {e}")

        # Save config used (drop the injected non-serializable Source handle).
        config_path = os.path.join(self.output_root, 'metadata', 'config_used.yaml')
        with open(config_path, 'w') as f:
            yaml.dump({k: v for k, v in self.config.items() if not k.startswith('_')},
                      f, default_flow_style=False)

        try:
            # Run collectors
            self._run_collectors()

            # Save legacy manifest (JSON + CSV + errors) inside the output tree.
            self.manifest.save_manifest_json()
            self.manifest.save_manifest_csv()
            self.manifest.save_errors_log()

            # Empty-collection guard (Talon parity): nothing collected -> rc=2.
            if self.session_result is not None and not self.session_result.artifacts:
                self.logger.warning("No artifacts collected")
                self.exit_code = 2

            # Emit content-addressed bundle if requested.
            bundle_path = None
            if self.output_format in ('bundle', 'both'):
                bundle_path = self._write_bundle()

            # Create ZIP unless bundle-only.
            zip_path = None
            if self.output_format in ('zip', 'both'):
                zip_path = self._create_zip()
        finally:
            # Always release the source (unmount raw device, close image).
            try:
                self.source.close()
            except Exception:
                pass
            if self.image:
                self.image.close()

        # Print summary
        self._print_summary(zip_path or bundle_path)
        return self.exit_code == 0

    def _run_collectors(self):
        """Run configured collectors via the HarvesterCollection orchestrator.

        Stores the sealed :class:`SessionResult` on ``self.session_result`` for
        bundle emission.
        """
        # Warn about any unknown/unresolvable categories up front.
        for cat in self.categories:
            if registry.get(cat) is None:
                self.logger.warning(f"Unknown category: {cat}")

        hostname = (
            Path(self.image_path).stem if self.image_path
            else os.environ.get('COMPUTERNAME', os.uname().nodename if hasattr(os, 'uname') else 'unknown')
        )
        collection = HarvesterCollection(
            config=self.config,
            source_root=str(self.source_root),
            output_root=self.output_root,
            level=self.level,
            manifest=self.manifest,
            category_keys=self.categories,
            image=self.image,
            source=self.source,
            session_id=self.base_output_dir,
            hostname=hostname,
            os_name=self.target_os,
            threads=self.threads,
            progress=not self.quiet,
        )
        collection.start()
        collection.collect()
        self.session_result = collection.finalize()
        self.logger.info(
            "Collected %d artifacts (%d bytes)",
            len(self.session_result.artifacts),
            self.session_result.total_bytes,
        )

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
            self.last_zip = zip_path

            # Remove uncompressed directory if requested (but keep it when a
            # bundle also needs the staged files).
            if not self.config.get('keep_unzipped', False) and self.output_format != 'both':
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

    def _write_bundle(self) -> Optional[str]:
        """Write the content-addressed artifact bundle (manifest/blobs/events)."""
        if self.session_result is None:
            return None
        from utils.bundle import BundleWriter
        from utils.contracts import ContractValidationError

        bundle_dir = os.path.join(
            self.config.get('output_dir', './output'),
            self.base_output_dir + '_bundle',
        )
        try:
            writer = BundleWriter(self.output_root, bundle_dir)
            writer.write(self.session_result, validate=True)
            self.logger.info(f"Wrote bundle: {bundle_dir}")
            return bundle_dir
        except ContractValidationError as e:
            self.logger.error(f"Bundle manifest failed contract validation: {e}")
            self.exit_code = 1
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
        description='Triager - Comprehensive Forensic Triage Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live triage - small level
  python triager.py --mode live --level small
  
  # Dead-box from raw dd image
  python triager.py --mode image --image-path disk.dd --level complete
  
  # Dead-box from mounted image
  python triager.py --mode image --image-path E:\\ --level complete
  
  # Exhaustive with YARA
  python triager.py --mode image --image-path disk.dd --yara-rules ./rules/
        """
    )

    parser.add_argument('--version', action='version',
                        version='CherryPick 1.2.0')

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
        '--categories', '--collect',
        dest='categories',
        type=str,
        help='Comma-separated list of categories to collect (--collect is an alias)'
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

    # Dead-box sources (Talon parity)
    parser.add_argument('--path', help='Dead-box: path to a mounted volume root')
    parser.add_argument('--disk', help='Dead-box: raw block device (e.g. /dev/sdb1)')
    parser.add_argument('--bitlocker-key', help='BitLocker recovery key/passphrase for --disk')

    # Output format
    parser.add_argument(
        '--output-format', choices=['zip', 'bundle', 'both'], default='zip',
        help='Output: password-zip, content-addressed bundle, or both (default: zip)'
    )

    # Remote upload (Talon parity)
    parser.add_argument('--api-url', help='Citadel API base URL for case upload')
    parser.add_argument('--case-id', help='Case ID for API upload')
    parser.add_argument('--api-token', help='Bearer token for API upload')
    parser.add_argument('--presigned-url', help='S3/MinIO presigned PUT URL for upload')

    # IOC fetch sweep
    parser.add_argument('--fetch', action='append', default=[],
                        help='IOC filename/glob or re:<regex> to sweep (repeatable)')
    parser.add_argument('--fetch-root', help='Root dir for --fetch sweep (default: source root)')
    parser.add_argument('--fetch-max-files', type=int, default=200)
    parser.add_argument('--fetch-max-mb', type=int, default=100)

    parser.add_argument('--dry-run', action='store_true',
                        help='Preview categories; collect nothing')
    parser.add_argument('--skip-problematic', action='store_true',
                        help='Skip categories known to fail on dead-box mounts')

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
    if args.path:
        config['path'] = args.path
    if args.disk:
        config['disk'] = args.disk
    if args.bitlocker_key:
        config['bitlocker_key'] = args.bitlocker_key
    if args.output_format:
        config['output_format'] = args.output_format
    if args.no_zip and config.get('output_format', 'zip') == 'zip':
        # --no-zip with default format means emit a bundle instead.
        config['output_format'] = 'bundle'
    if args.api_url:
        config['api_url'] = args.api_url
    if args.case_id:
        config['case_id'] = args.case_id
    if args.api_token:
        config['api_token'] = args.api_token
    if args.presigned_url:
        config['presigned_url'] = args.presigned_url
    if args.fetch:
        config['fetch'] = args.fetch
        config['fetch_root'] = args.fetch_root
        config['fetch_max_files'] = args.fetch_max_files
        config['fetch_max_mb'] = args.fetch_max_mb
        # Ensure the file_search category runs when IOCs are requested.
        cats = config.get('categories') or []
        if cats and 'file_search' not in cats:
            cats.append('file_search')
            config['categories'] = cats
    if args.dry_run:
        config['dry_run'] = True
    if args.skip_problematic:
        config['skip_problematic'] = True

    # Create and run harvester
    harvester = Triager(config)

    try:
        harvester.run()
        _maybe_upload(harvester, config)
        sys.exit(harvester.exit_code)
    except KeyboardInterrupt:
        print("\nCollection interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _maybe_upload(harvester, config):
    """Upload the produced artifact (zip/bundle) if an upload target is set."""
    if harvester.dry_run or harvester.exit_code not in (0, 2):
        return
    presigned = config.get('presigned_url')
    api_url = config.get('api_url')
    if not (presigned or api_url):
        return
    try:
        import remote_upload
    except Exception as e:
        print(f"upload skipped (remote_upload unavailable): {e}")
        return
    # Prefer the zip artifact; fall back to bundle dir.
    target = getattr(harvester, 'last_zip', None)
    if not target:
        print("upload skipped: no zip artifact (bundle upload not yet wired)")
        return
    try:
        if presigned:
            remote_upload.upload_via_presigned(target, presigned)
        elif api_url and config.get('case_id'):
            remote_upload.upload_to_fo(target, api_url, config['case_id'], config.get('api_token', ''))
    except Exception as e:
        print(f"upload failed: {e}")


if __name__ == '__main__':
    main()
