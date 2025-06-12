"""
ioc_topus.config
~~~~~~~~~~~~~~~~
• Loads API-keys and other settings from the user’s environment or
  the project-root “.env” file (via python-dotenv).

• Exposes convenience constants   VT_API_KEY, URLSCAN_API_KEY, VALIDIN_API_KEY
  that other modules import.

• Provides ``persist_api_keys()`` so the GUI can write fresh keys back
  to .env and refresh the current process without restarting.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Optional

from dotenv import load_dotenv, set_key as _set_key

# Import the decryption utility
from ioc_topus.utils.crypto import decrypt_string, get_cipher



# ---------------------------------------------------------------------------#
# 1) Locate & load the .env file *once*
# ---------------------------------------------------------------------------#
ROOT: Final[Path] = Path(__file__).resolve().parent.parent   # project root
ENV_FILE: Final[Path] = ROOT / ".env"

load_dotenv(ENV_FILE, override=False)       # does nothing if the file is absent



# Helper function to safely decrypt a value
def _get_and_decrypt_env(var_name: str) -> str:
    """Gets an environment variable and attempts to decrypt it."""
    encrypted_val = os.getenv(var_name, "")
    if not encrypted_val:
        return ""
    try:
        # This initializes the cipher if it hasn't been already
        get_cipher() 
        return decrypt_string(encrypted_val)
    except Exception:
        # If decryption fails, it's likely a plaintext key from an old version.
        # We can return it as-is for backward compatibility.
        return encrypted_val



# ---------------------------------------------------------------------------#
# 2) Public constants used throughout the code-base
# ---------------------------------------------------------------------------#

# Use the new decryption helper to load keys
VT_API_KEY:  str = _get_and_decrypt_env("VIRUSTOTAL_API_KEY")
URLSCAN_API_KEY: str = _get_and_decrypt_env("SECURITYTRAILS_API_KEY")
VALIDIN_API_KEY: str = _get_and_decrypt_env("VALIDIN_API_KEY")



# ---------------------------------------------------------------------------#
# 3) Runtime update helper – GUI calls this on *Apply*
# ---------------------------------------------------------------------------#
def persist_api_keys(
    *,
    vt: Optional[str] = None,
    urlscan: Optional[str] = None,
    validin: Optional[str] = None,
    env_path: Path | None = None,
) -> None:
    """
    Write new API keys to the ``.env`` file **and** update ``os.environ`` so
    the running application (and cached singletons) can use them immediately.

    NOTE: This function now expects to receive ENCRYPTED values from the GUI.

    Parameters
    ----------
    vt : str | None
        New ENCRYPTED VirusTotal key.
    urlscan : str | None
        New ENCRYPTED urlscan / SecurityTrails key.
    validin : str | None
        New ENCRYPTED Validin key.
    env_path : pathlib.Path | None
        Custom path for the .env file (defaults to project-root/.env).
    """
    env_path = env_path or ENV_FILE

    def _update(var_name: str, new_encrypted_val: Optional[str]) -> None:
        if new_encrypted_val:
            # Store the encrypted value in the .env file
            os.environ[var_name] = new_encrypted_val
            _set_key(str(env_path), var_name, new_encrypted_val)

    _update("VIRUSTOTAL_API_KEY",     vt)
    _update("SECURITYTRAILS_API_KEY", urlscan)
    _update("VALIDIN_API_KEY",        validin)

    # refresh module-level constants *for this import only*
    # This ensures the new keys are available immediately in the running app
    global VT_API_KEY, URLSCAN_API_KEY, VALIDIN_API_KEY
    VT_API_KEY        = _get_and_decrypt_env("VIRUSTOTAL_API_KEY")
    URLSCAN_API_KEY   = _get_and_decrypt_env("SECURITYTRAILS_API_KEY")
    VALIDIN_API_KEY   = _get_and_decrypt_env("VALIDIN_API_KEY")


# ---------------------------------------------------------------------------#
# 4) Explicit public surface
# ---------------------------------------------------------------------------#
__all__ = [
    "ROOT",
    "ENV_FILE",
    "VT_API_KEY",
    "URLSCAN_API_KEY",
    "VALIDIN_API_KEY",
    "persist_api_keys",
]