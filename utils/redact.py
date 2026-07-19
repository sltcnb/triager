"""Redaction helpers for secret-bearing CLI arguments.

Chain-of-custody metadata embedded in the (Ed25519-signed) bundle manifest
records the exact command line the operator invoked (``sys.argv``) so a
third party can later audit how a collection was produced. Several CLI flags
accept secrets in plaintext on that command line — a BitLocker recovery
key/passphrase, a bearer token for API upload, a ZIP password, a presigned
upload URL carrying a signature — and those must never be persisted verbatim
into evidence that is shared outside the operator's own machine.

This module centralises the "does this flag carry a secret" policy so it can
be applied anywhere an argv-like list of strings is captured for storage.
"""

from __future__ import annotations

import re
from typing import List, Sequence

REDACTED = "[REDACTED]"

# Known flag names (long form, without leading dashes) that carry secrets.
# Compared case-insensitively with underscores normalised to hyphens, so
# both ``--bitlocker-key`` and an argparse-style ``bitlocker_key`` match.
SENSITIVE_FLAGS = frozenset(
    {
        "bitlocker-key",
        "api-token",
        "zip-password",
        "presigned-url",
    }
)

# Generic heuristic: catch anything *named* like a secret even if it is not
# in the explicit list above (new flags, third-party wrappers, typos). This
# is intentionally broad — false positives just redact a harmless value,
# false negatives leak a secret into signed evidence.
_SENSITIVE_NAME_RE = re.compile(
    r"(key|token|secret|password|passwd|pwd|credential|apikey|auth)",
    re.IGNORECASE,
)


def _flag_name(arg: str) -> str:
    """Normalize ``--Some_Flag`` / ``-Some-Flag=x`` down to ``some-flag``."""
    name = arg.split("=", 1)[0].lstrip("-")
    return name.replace("_", "-").lower()


def is_sensitive_flag(arg: str) -> bool:
    """Return True if *arg* looks like a flag whose value must not be logged."""
    if not arg.startswith("-"):
        return False
    name = _flag_name(arg)
    return name in SENSITIVE_FLAGS or bool(_SENSITIVE_NAME_RE.search(name))


def redact_argv(argv: Sequence[str]) -> List[str]:
    """Return a copy of *argv* with secret-bearing flag values replaced.

    Handles both the two-token form (``--api-token VALUE``) and the
    single-token form (``--api-token=VALUE``). Everything else is passed
    through unchanged.
    """
    redacted: List[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append(REDACTED)
            redact_next = False
            continue
        if is_sensitive_flag(arg):
            if "=" in arg:
                flag, _, _value = arg.partition("=")
                redacted.append(f"{flag}={REDACTED}")
            else:
                redacted.append(arg)
                redact_next = True
        else:
            redacted.append(arg)
    return redacted
