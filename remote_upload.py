#!/usr/bin/env python3
"""
Artifact upload helpers (ported from Talon collect.py).

Three stdlib-only delivery paths for a produced artifact (zip or bundle file):

* :func:`upload_via_presigned` — HTTP PUT to an S3/MinIO presigned URL.
* :func:`upload_log_via_presigned` — best-effort PUT of the execution log.
* :func:`upload_to_fo` — multipart POST to the Citadel case ingest API.

Unlike Talon's originals these raise :class:`UploadError` instead of calling
``sys.exit`` so they compose as a library; callers decide how to react.
"""

from __future__ import annotations

import logging
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

logger = logging.getLogger(__name__)


class UploadError(RuntimeError):
    """Raised on any upload failure."""


def _ssl_ctx() -> ssl.SSLContext:
    """TLS context for uploads — verifying by default.

    Evidence in transit must be tamper-evident, so certificates are verified.
    For internal MinIO deployments with a private CA, point
    ``CHERRYPICK_CA_BUNDLE`` at the CA PEM instead of disabling verification.

    Verification can be disabled only by explicitly setting
    ``CHERRYPICK_INSECURE_TLS=1`` (logged loudly) — never silently.
    """
    ca_bundle = os.environ.get("CHERRYPICK_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=ca_bundle or None)
    if os.environ.get("CHERRYPICK_INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        logger.warning(
            "CHERRYPICK_INSECURE_TLS set — TLS certificate verification DISABLED. "
            "Uploaded evidence is exposed to undetectable MITM tampering."
        )
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def upload_via_presigned(zip_path: PathLike, presigned_url: str) -> None:
    """HTTP PUT to a pre-signed S3/MinIO URL — no credentials at runtime."""
    zip_path = Path(zip_path)
    print(f"\n  [*] Uploading {zip_path.name} -> S3 (presigned URL)")
    with open(zip_path, "rb") as fh:
        file_data = fh.read()
    req = urllib.request.Request(
        presigned_url, data=file_data,
        headers={"Content-Type": "application/zip"}, method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=600, context=_ssl_ctx()) as resp:
            print(f"  [+] Upload successful (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        raise UploadError(f"HTTP {exc.code}: {exc.read(256).decode(errors='replace')}") from exc
    except Exception as exc:
        raise UploadError(str(exc)) from exc


def upload_log_via_presigned(log_path: PathLike, presigned_url: str) -> bool:
    """Best-effort PUT of the execution log. Never raises."""
    log_path = Path(log_path)
    if not log_path.exists():
        return False
    try:
        data = log_path.read_bytes()
    except Exception:
        return False
    req = urllib.request.Request(
        presigned_url, data=data,
        headers={"Content-Type": "text/plain; charset=utf-8"}, method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=120, context=_ssl_ctx()) as resp:
            print(f"  [+] Execution log uploaded (HTTP {resp.status})")
            return True
    except Exception as exc:
        print(f"  [!] Execution-log upload failed: {exc}")
        return False


def upload_to_fo(zip_path: PathLike, api_url: str, case_id: str, api_token: str = "") -> None:
    """Multipart POST to the Citadel case ingest endpoint."""
    zip_path = Path(zip_path)
    url = f"{api_url.rstrip('/')}/cases/{case_id}/ingest"
    boundary = f"fh_boundary_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    print(f"\n  [*] Uploading {zip_path.name} -> {url}")
    with open(zip_path, "rb") as fh:
        file_data = fh.read()
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files"; filename="{zip_path.name}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode()
        + file_data
        + f"\r\n--{boundary}--\r\n".encode()
    )
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            print(f"  [+] Upload successful (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise UploadError("HTTP 401 Unauthorized — pass --api-token <JWT>") from exc
        raise UploadError(f"HTTP {exc.code}: {exc.read(256).decode(errors='replace')}") from exc
    except Exception as exc:
        raise UploadError(str(exc)) from exc
