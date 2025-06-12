"""
ioc_topus.utils.helpers
~~~~~~~~~~~~~~~~~~~~~~~
Miscellaneous utility helpers that do **not** depend on any external
service or on Tkinter.  Keep it import-cycle-free!
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# 1) Timestamp conversion
# ---------------------------------------------------------------------------
from datetime import datetime, timezone


def convert_timestamp(ts):
    """Convert a UNIX timestamp→`YYYY-MM-DD HH:MM:SS UTC` or return str(ts) on error."""
    if ts:
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        except (TypeError, ValueError, OSError):
            return str(ts)
    return None


# ---------------------------------------------------------------------------
# 2) String / IP helpers for Lucene-style search back-ends (urlscan etc.)
# ---------------------------------------------------------------------------
def escape_ip(ip_str: str) -> str:
    """Escape dots so the IP can be dropped straight into a Lucene query."""
    return ip_str.replace(".", r"\.")


def escape_filename(value: str) -> str:
    """Escape backslashes, dots and colons for urlscan’s filename search."""
    return value.replace("\\", r"\\").replace(".", r"\.").replace(":", r"\:")


def is_ip_address(host: str) -> bool:
    """Cheap test to avoid pulling in `ipaddress` for a simple true/false."""
    stripped = host.split(":")[0]
    return bool(re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", stripped))


def parse_url_for_queries(url_ioc: str) -> list[str]:
    """
    Turn *anything* the user pastes (URL, domain, IP, file name) into the list
    of urlscan query clauses we want to run.
    """
    if not re.match(r"^\w+://", url_ioc):
        url_ioc = "http://" + url_ioc

    parsed = urlparse(url_ioc)
    host = parsed.netloc
    if not host:                       # very odd input → treat as filename
        esc_fn = escape_filename(url_ioc)
        return [f'filename:"{esc_fn}"']

    queries: list[str] = []
    if is_ip_address(host):
        ip_only = host.split(":")[0]
        queries.append(f"ip:{escape_ip(ip_only)}")
    else:
        domain_only = host.split(":")[0]
        queries.append(f"domain:{domain_only}")

    queries.append(f'filename:"{escape_filename(url_ioc)}"')
    return queries


# ---------------------------------------------------------------------------
# 3) Tiny convenience pivot (used by GUI right-click & potential CLI)
# ---------------------------------------------------------------------------
def pivot_bodyhash_search(body_hash: str) -> None:
    """Open the default browser at urlscan’s body-hash search for this hash."""
    import webbrowser

    webbrowser.open(f"https://urlscan.io/search/#{body_hash}")


__all__ = [
    "convert_timestamp",
    "escape_ip",
    "escape_filename",
    "is_ip_address",
    "parse_url_for_queries",
    "pivot_bodyhash_search",
]
