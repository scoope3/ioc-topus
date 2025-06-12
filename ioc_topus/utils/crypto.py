"""
ioc_topus.utils.crypto
~~~~~~~~~~~~~~~~~~~~~~
Key-management and encryption helpers.

* Generates (once) a 32-byte Fernet key and stores it at
  ~/.ioc_topus_key   ← easy to keep out of the repo.
* Exposes a **singleton** `Fernet` instance via `get_cipher()`.
* Thin wrappers `encrypt_string` / `decrypt_string` call that cipher.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# 1) Where we persist the master key
# ---------------------------------------------------------------------------
_KEY_PATH: Final[Path] = Path.home() / ".ioc_topus_key"


def get_or_create_master_key() -> bytes:
    """
    Return the 32-byte key (in raw bytes) for Fernet.
    If the file doesn’t exist we create it *once* and chmod 600 on POSIX.
    """
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()

    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)

    # Optional: restrict permissions (ignored on Windows)
    try:
        _KEY_PATH.chmod(0o600)  # rw-------
    except OSError:
        pass

    return key


# ---------------------------------------------------------------------------
# 2) The **exported helper** every other module should import
# ---------------------------------------------------------------------------
_cipher: Fernet | None = None          # module-level cache (lazy singleton)


def get_cipher() -> Fernet:
    """
    Return a *single* Fernet object initialised with the master key.
    Callers never re-create their own cipher; they just `from ... import get_cipher`.
    """
    global _cipher
    if _cipher is None:
        _cipher = Fernet(get_or_create_master_key())
    return _cipher


# ---------------------------------------------------------------------------
# 3) Convenience wrappers kept for backwards-compatibility
# ---------------------------------------------------------------------------
def encrypt_string(plaintext: str) -> str:
    """Encrypt `plaintext` → base64 text token."""
    return get_cipher().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_string(ciphertext: str) -> str:
    """Decrypt base64 `ciphertext` back to plain text."""
    return get_cipher().decrypt(ciphertext.encode("utf-8")).decode("utf-8")

# ---------------------------------------------------------------------------
# 3b) Optional helper – rotate the master Fernet key
# ---------------------------------------------------------------------------
def set_key(new_key: bytes | str) -> None:
    """
    Overwrite ~/.ioc_topus_key with *new_key*.

    Accepts raw bytes or a base-64/utf-8 string. Subsequent calls to
    `get_cipher()` will use the new key (the cache is refreshed).
    """
    global _cipher

    if isinstance(new_key, str):
        new_key = new_key.encode("utf-8")

    _KEY_PATH.write_bytes(new_key)
    try:
        _KEY_PATH.chmod(0o600)
    except OSError:
        pass

    _cipher = Fernet(new_key)  # refresh the singleton


# ---------------------------------------------------------------------------
# 4) Explicit public surface (optional but tidy)
# ---------------------------------------------------------------------------
__all__ = [
    "get_or_create_master_key",
    "get_cipher",
    "encrypt_string",
    "decrypt_string",
    "set_key",                    
]
