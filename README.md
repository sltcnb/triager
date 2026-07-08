<p align="center"><img src="docs/banner.png" alt="Triager" width="100%"></p>


## Demo

<p align="center"><img src="docs/demo.gif" alt="triager demo" width="100%"></p>

# triager

A comprehensive, cross-OS forensic acquisition agent. It walks a host (live), a
mounted volume, a pytsk3 disk image (E01/dd/vhd), or a raw device (BitLocker) and
gathers artifacts into a **signed, content-addressed bundle** — the same contract
Citadel's Talon produces — while keeping Triager's strengths (pytsk3
imaging, YARA, multithreading) and one-file-per-collector modularity.

## What's new (v1.2.0 — Talon parity)

- **Cross-OS catalog** — 70 collectors: 52 Windows, 11 Linux, 7 macOS.
- **Content-addressed bundle** — `manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256`, conforming to the vendored `contracts/bundle_manifest.schema.json`; manifest is schema-validated before sealing. `--output-format {zip,bundle,both}`.
- **Capabilities catalog** — `capabilities.yaml` is the single source of truth for what is collectable (renderable as a UI). Its option `value`s are the `--collect` keys, validated against the collector registry at startup.
- **Auto-discovery registry** — collectors self-register by class; adding one is a single new file (no more 3-place dispatch tables). Talon category keys (`evtx`, `network_cfg`, …) work as aliases.
- **Unified source abstraction** (`sources/`) — one collector body runs against live FS, mounted volume, pytsk3 image, or raw device+BitLocker (dislocker→cryptsetup, ntfs-3g).
- **Dead-box** — `--path <mount>`, `--disk <device> --bitlocker-key <key>`, plus the existing `--image-path`.
- **IOC sweep** — `--fetch "mimikatz*" --fetch "re:\.(ps1|hta)$" --fetch-root C:\Users`.
- **Remote delivery** — gRPC/mTLS agent, AES-256-GCM chunked resumable upload, S3/MinIO presigned + Citadel case API (`--api-url/--case-id/--api-token`, `--presigned-url`). All optional/lazy-imported.
- **Finished collectors** — `hashing` (MD5/SHA256 inventory), `file_listing` (recursive MACB), `yara` (rule scan → match JSONL) are implemented.
- **Tests** — `pytest tests/` (chunker, secure-upload, registry consistency, source+bundle schema, stub collectors).

## Features

- **Two Operation Modes**:
  - Live system mode: Collect from a running Windows machine
  - Dead-box mode: Collect from a mounted dd image

- **Three Collection Levels**:
  - `small`: Fast triage with highest-value artifacts
  - `complete`: Comprehensive collection of all common artifacts
  - `exhaustive`: Full forensic collection with advanced features

- **50+ Artifact Categories**:
  - Registry hives and user profiles
  - Event logs (Security, System, Application, PowerShell, Sysmon, etc.)
  - Filesystem artifacts ($MFT, $UsnJrnl, ADS)
  - Execution artifacts (Prefetch, Superfetch, SRUM, Amcache, Shimcache, BAM)
  - Persistence mechanisms (Autoruns, Scheduled Tasks, Services, WMI)
  - Network configuration and history
  - USB device history
  - Browser artifacts (Chrome, Firefox, Edge, IE)
  - Email data (Outlook, Thunderbird)
  - Messaging apps (Teams, Slack, Discord, Signal, WhatsApp, Telegram)
  - Cloud storage (OneDrive, Google Drive, Dropbox)
  - Remote access tools (AnyDesk, TeamViewer, RDP, SSH)
  - Credentials and authentication data
  - Antivirus/EDR logs
  - And many more...

- **Deterministic Output Structure**: Every file is placed at a predictable path for automated analysis

- **Parallel Collection**: Multi-threaded collection for faster triage

- **Comprehensive Manifest**: JSON and CSV manifests tracking all collected files with hashes

- **ZIP Output**: Automatic creation of password-protected ZIP archives (ZIP64 support for >4GB)

## Installation

```bash
# Clone or download the tool
cd triager

# Install dependencies
pip install -r requirements.txt
```

### Optional Dependencies

For full functionality, install optional dependencies:

```bash
pip install yara-python regipy pytsk3 pyewf pycryptodome pyzipper pywin32
```

- `yara-python`: YARA rule scanning
- `regipy`: Offline registry parsing
- `pytsk3`: Raw NTFS access
- `pyewf`: E01/EWF image support
- `pycryptodome`: Cryptographic operations
- `pyzipper`: Password-protected ZIP
- `pywin32`: Windows API access (Windows only)

## Usage

### Basic Examples

```bash
# Live triage - small level (fast)
python triager.py --mode live --level small

# Live triage - complete level
python triager.py --mode live --level complete

# Dead-box against mounted image
python triager.py --mode image --image-path E:\ --level complete

# Collect specific categories
python triager.py --mode live --level complete --categories registry,eventlogs,browser_all

# With password-protected ZIP
python triager.py --mode live --level complete --zip-password "S3cur3P@ss!"

# Exhaustive mode with YARA scanning
python triager.py --mode image --image-path E:\ --level exhaustive --yara-rules ./rules/
```

### Command Line Options

```
usage: triager.py [-h] (--mode {live,image} | --image-path IMAGE_PATH)
                             [--level {small,complete,exhaustive}]
                             [--categories CATEGORIES]
                             [--include-users INCLUDE_USERS]
                             [--output-dir OUTPUT_DIR]
                             [--zip-password ZIP_PASSWORD]
                             [--keep-unzipped] [--no-zip]
                             [--threads THREADS]
                             [--yara-rules YARA_RULES]
                             [--collect-pagefile] [--collect-hiberfil]
                             [--collect-swapfile] [--config CONFIG]
                             [--quiet] [--max-file-size MAX_FILE_SIZE]

Triager - Comprehensive Forensic Triage Tool

options:
  -h, --help            show this help message and exit
  --mode {live,image}   Collection mode: live system or mounted image
  --image-path IMAGE_PATH
                        Path to mounted dd image (implies --mode image)
  --level {small,complete,exhaustive}
                        Collection level (default: complete)
  --categories CATEGORIES
                        Comma-separated list of categories to collect
  --include-users INCLUDE_USERS
                        Comma-separated list of usernames to collect
  --output-dir OUTPUT_DIR
                        Output directory (default: ./output)
  --zip-password ZIP_PASSWORD
                        Password for ZIP encryption
  --keep-unzipped       Keep uncompressed output directory
  --no-zip              Skip ZIP creation
  --threads THREADS     Number of parallel threads (default: 4)
  --yara-rules YARA_RULES
                        Path to YARA rules file or directory
  --collect-pagefile    Collect pagefile.sys
  --collect-hiberfil    Collect hiberfil.sys
  --collect-swapfile    Collect swapfile.sys
  --config CONFIG       Path to configuration file (default: config.yaml)
  --quiet               Suppress stdout output
  --max-file-size MAX_FILE_SIZE
                        Maximum file size in MB (0 = no limit)
```

### Configuration File

Create a `config.yaml` file for default settings:

```yaml
mode: live
level: complete
categories: []
output_dir: ./output
threads: 4
zip_password: null
keep_unzipped: false
hash_collected: true
max_file_size_mb: 0
```

CLI flags override configuration file values.

## Output Structure

```
Triager_HOSTNAME_YYYYMMDD_HHMMSS/
├── metadata/
│   ├── collection_manifest.json
│   ├── collection_log.txt
│   ├── system_info.json
│   ├── config_used.yaml
│   └── errors.log
├── registry/
│   ├── SYSTEM
│   ├── SOFTWARE
│   ├── SAM
│   ├── SECURITY
│   └── users/
│       └── <username>/
│           ├── NTUSER.DAT
│           └── UsrClass.dat
├── eventlogs/
│   ├── Security.evtx
│   ├── System.evtx
│   └── ...
├── filesystem/
│   ├── $MFT
│   ├── $LogFile
│   └── ...
├── execution/
│   ├── prefetch/
│   ├── superfetch/
│   └── ...
└── ... (50+ categories)
```

## Collection Levels

### Small
Fast triage (~5-15 minutes):
- Registry hives
- Critical event logs
- Prefetch
- Amcache
- Shimcache/BAM
- SRUM
- PowerShell history
- Basic browser history
- Scheduled tasks
- Services
- Windows Defender logs

### Complete
Comprehensive collection (~30-90 minutes):
- Everything in Small, plus:
- All event logs
- Full $MFT
- All user hives
- Full browser profiles
- Email artifacts
- Messaging apps
- Cloud storage
- Remote access tools
- SSH/FTP configs
- Credential stores
- Antivirus/EDR logs
- IIS logs
- Boot artifacts
- And more...

### Exhaustive
Full forensic collection (hours):
- Everything in Complete, plus:
- Full pagefile/hiberfil/swapfile
- Volume Shadow Copy extraction
- YARA scanning
- Entropy analysis
- Full volume file listing
- Hashing of all executables
- Deleted MFT entry carving

## Category Shortcuts

Use these shortcuts in `--categories`:
- `browser_all`: Chrome + Firefox + Edge + IE
- `email_all`: Outlook + Thunderbird + Other
- `messaging_all`: Teams + Slack + Discord + Signal + WhatsApp + Telegram
- `cloud_all`: OneDrive + Google Drive + Dropbox + Other

## System Requirements

- Python 3.8+
- Windows 7/8/10/11 or Server 2012-2022
- Administrator/SYSTEM privileges for live collection
- Sufficient disk space for collected artifacts

## Notes

### Live Collection
- Requires administrator or SYSTEM privileges
- Some files may be locked (pagefile, registry hives)
- Uses Volume Shadow Copy when available

### Image Collection
- Mount dd images with FTK Imager, Arsenal Image Mounter, or similar
- Read-only access recommended
- All files should be accessible

### Deterministic Naming
Every collected file follows a deterministic naming convention so downstream analysis tools can locate files by path alone.

## License

MIT License

## Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## Disclaimer

This tool is for authorized forensic analysis only. Ensure you have proper legal authority before collecting data from any system.
