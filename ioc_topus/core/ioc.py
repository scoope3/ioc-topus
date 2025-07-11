"""
ioc_topus.core.ioc
~~~~~~~~~~~~~~~~~~
Tiny helpers for recognising and carrying Indicators of Compromise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------#
# 1)  Low-level type detection helper 
# ---------------------------------------------------------------------------#
def validate_ioc(ioc: str) -> Literal["url", "ip_address", "domain", "file_hash", "fingerprint_hash"]:
    """
    Return the canonical IOC type or raise ``ValueError`` if *ioc* is invalid.

    * url         – anything starting with http:// or https://
    * ip_address  – IPv4 dotted-quad
    * domain      – example.com / sub.example.co.uk
    * file_hash   – MD5 / SHA-1 / SHA-256 / SHA-512 / TLSH / etc.
    * fingerprint_hash – JARM / other fingerprints (for Validin pivots)
    """
    # 1. URL
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"

    # 2. IPv4
    ip_re = (
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
    )
    if re.match(ip_re, ioc):
        return "ip_address"

    # 3. Domain
    dom_re = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"
    if re.match(dom_re, ioc):
        return "domain"

    # 4. Hex hashes
    if re.match(r"^[A-Fa-f0-9]+$", ioc):
        length = len(ioc)
        
        # Standard file hashes - only for specific known lengths
        if length == 128:  # SHA-512
            return "file_hash"
        elif length == 64:  # SHA-256
            return "file_hash"
        elif length == 40:  # SHA-1
            return "file_hash"
        elif length in [70, 71, 72]:  # TLSH
            return "file_hash"
        
        # For 32-char hashes, we need to decide between MD5 and fingerprint
        # Since Validin uses these for fingerprints, default to fingerprint_hash
        # unless user explicitly wants file hash behavior
        elif length == 32:  # Could be MD5 or fingerprint
            return "fingerprint_hash"  # Default to fingerprint for Validin
        
        # JARM fingerprints
        elif length == 62:
            return "fingerprint_hash"
        
        # Any other hex string between 8-128 chars is likely a fingerprint
        elif 8 <= length <= 128:
            return "fingerprint_hash"

    raise ValueError(f"Invalid IOC format: {ioc!r}")


# ---------------------------------------------------------------------------#
# 2)  Convenience dataclass
# ---------------------------------------------------------------------------#
@dataclass(frozen=True, slots=True)
class IOC:
    """
    Immutable container for a single IOC.

    Examples
    --------
    >>> IOC("8.8.8.8").type
    'ip_address'
    >>> IOC("http://evil.biz/path").value
    'http://evil.biz/path'
    """

    value: str
    type: Literal["url", "ip_address", "domain", "file_hash"]

    # We derive `type` automatically if caller passes only `value`.
    def __init__(self, value: str, ioc_type: str | None = None):
        if ioc_type is None:
            ioc_type = validate_ioc(value)
        elif ioc_type not in ("url", "ip_address", "domain", "file_hash", "fingerprint_hash"):
            raise ValueError(f"Unsupported IOC type {ioc_type!r}")

        # Bypass frozen check
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "type", ioc_type)

    # handy stringification
    def __str__(self) -> str: 
        return self.value

    def __repr__(self) -> str:
        return f"IOC(value={self.value!r}, type={self.type!r})"


# ---------------------------------------------------------------------------#
# 3)  Public exports
# ---------------------------------------------------------------------------#
__all__ = ["validate_ioc", "IOC"]
