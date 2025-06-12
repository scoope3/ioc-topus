"""
ioc_topus.core.processor
~~~~~~~~~~~~~~~~~~~~~~~~
Glue layer that calls the individual API clients, parses their
responses, and merges everything into the canonical 5-tuple that the
GUI (or CLI) expects:

    (ioc, ioc_type, combined_data_dict, combined_sources, final_error)
"""

from __future__ import annotations

import re
from queue import Queue
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
from urllib.parse import urlparse

# ────────────────────────────────#
#  Package imports
# ────────────────────────────────#
from ioc_topus.core.ioc import validate_ioc
from ioc_topus.core.merge import merge_api_results
from ioc_topus.api.virustotal import (
    VirusTotalClient,
    parse_virustotal_response,
)
from ioc_topus.api.urlscan import UrlscanClient
from ioc_topus.api.validin import query_validin_domain, query_validin_ip

# ────────────────────────────────#
#  Re-use *one* client per API
# ────────────────────────────────#
#VT_CLIENT = VirusTotalClient()   # reads key from .env
#US_CLIENT = UrlscanClient()      # reads key from .env

_VT_CLIENT: VirusTotalClient | None = None
_US_CLIENT: UrlscanClient | None = None


def _get_vt_client() -> VirusTotalClient:
    global _VT_CLIENT
    if _VT_CLIENT is None:
        _VT_CLIENT = VirusTotalClient()          # reads key from os.environ
    return _VT_CLIENT


def _get_us_client() -> UrlscanClient:
    global _US_CLIENT
    if _US_CLIENT is None:
        _US_CLIENT = UrlscanClient()             # reads key from os.environ
    return _US_CLIENT

# ---------------------------------------------------------------------------#
# 1)  High-level helper
# ---------------------------------------------------------------------------#
def _get_first_5tuple(q: Queue) -> Tuple[str, str, dict | None, List[str], str | None]:
    """
    Block until the worker queue *q* has one item and return it as a
    guaranteed 5-tuple (padding with ``None`` if the worker produced the
    old 4-tuple shape).
    """
    tup = q.get(block=True)
    if len(tup) == 5:
        return tup  # already correct shape
    ioc, ioc_type, data_dict, srcs = tup
    return ioc, ioc_type, data_dict, srcs, None


# ---------------------------------------------------------------------------#
# 2)  Fetch + parse with both APIs
# ---------------------------------------------------------------------------#
def fetch_and_parse_ioc(ioc_str: str, results_queue: Queue) -> None:
    """
    Worker that queries **both** VirusTotal and urlscan, does URL→domain/IP
    expansion, merges results, and puts the final 5-tuple on `results_queue`.
    """
    try:
        ioc_type_val = validate_ioc(ioc_str)

        # ── 1) VirusTotal ───────────────────────────────────────────
        vt_q: Queue = Queue()
        _get_vt_client().query_ioc(ioc_str, ioc_type_val, vt_q)
        vt_ioc, vt_type, vt_raw, vt_srcs, vt_err = _get_first_5tuple(vt_q)
        vt_parsed = (
            parse_virustotal_response(vt_raw, vt_type)
            if vt_raw and vt_err is None
            else None
        )
        vt_tuple = (vt_ioc, vt_type, vt_parsed, vt_srcs, vt_err)

        # ── 2) urlscan / SecurityTrails ─────────────────────────────
        us_q: Queue = Queue()
        _get_us_client().query_ioc(ioc_str, ioc_type_val, us_q)
        us_tuple = _get_first_5tuple(us_q)

        # ── 3) Merge main IOC results ───────────────────────────────
        merged_ioc, merged_type, merged_data, merged_srcs, merged_error = merge_api_results(
            vt_tuple, us_tuple
        )

        # -------------------------------------------------------------------
        # 4) URL expansion → query domain/IP for extra pivots
        # -------------------------------------------------------------------
        if ioc_type_val == "url":
            domain = urlparse(ioc_str).netloc.split(":")[0]
            if domain:
                ip_re = r"^(?:\d{1,3}\.){3}\d{1,3}$"
                vt_dom_q: Queue = Queue()
                if re.match(ip_re, domain):
                    _get_vt_client().query_ioc(domain, "ip_address", vt_dom_q)
                else:
                    _get_vt_client().query_ioc(domain, "domain", vt_dom_q)
                vt_dom_tuple = _get_first_5tuple(vt_dom_q)
                vt_dom_parsed = (
                    parse_virustotal_response(vt_dom_tuple[2], vt_dom_tuple[1])
                    if vt_dom_tuple[2] and vt_dom_tuple[4] is None
                    else None
                )
                vt_dom_tuple = (
                    vt_dom_tuple[0],
                    vt_dom_tuple[1],
                    vt_dom_parsed,
                    vt_dom_tuple[3],
                    vt_dom_tuple[4],
                )

                us_dom_q: Queue = Queue()
                if re.match(ip_re, domain):
                    _get_us_client().query_ioc(domain, "ip_address", us_dom_q)
                else:
                    _get_us_client().query_ioc(domain, "domain", us_dom_q)
                us_dom_tuple = _get_first_5tuple(us_dom_q)

                # Merge pivot results into the main
                merged_ioc, merged_type, merged_data, merged_srcs, merged_error = merge_api_results(
                    (merged_ioc, merged_type, merged_data, merged_srcs, merged_error),
                    vt_dom_tuple,
                    us_dom_tuple,
                )

        # ── 5)  Push final tuple to caller
        results_queue.put((merged_ioc, merged_type, merged_data, merged_srcs, merged_error))

    except Exception as exc: 
        results_queue.put((ioc_str, None, None, [], str(exc)))


# ---------------------------------------------------------------------------#
# 3)  VT-only & urlscan-only workers
# ---------------------------------------------------------------------------#
def fetch_and_parse_ioc_vtonly(ioc_str: str, results_queue: Queue) -> None:
    """
    Same logic as before, but only VirusTotal (plus URL→domain/IP pivot).
    """
    try:
        ioc_type_val = validate_ioc(ioc_str)

        vt_q: Queue = Queue()
        _get_vt_client().query_ioc(ioc_str, ioc_type_val, vt_q)
        vt_ioc, vt_type, vt_raw, vt_srcs, vt_err = _get_first_5tuple(vt_q)
        vt_parsed = (
            parse_virustotal_response(vt_raw, vt_type) if vt_raw and vt_err is None else None
        )
        vt_tuple = (vt_ioc, vt_type, vt_parsed, vt_srcs, vt_err)

        merged_ioc, merged_type, merged_data, merged_srcs, merged_error = vt_tuple

        if ioc_type_val == "url":
            domain = urlparse(ioc_str).netloc.split(":")[0]
            if domain:
                ip_re = r"^(?:\d{1,3}\.){3}\d{1,3}$"
                vt_dom_q: Queue = Queue()
                if re.match(ip_re, domain):
                    _get_vt_client().query_ioc(domain, "ip_address", vt_dom_q)
                else:
                    _get_vt_client().query_ioc(domain, "domain", vt_dom_q)
                vt_dom_tuple = _get_first_5tuple(vt_dom_q)
                vt_dom_parsed = (
                    parse_virustotal_response(vt_dom_tuple[2], vt_dom_tuple[1])
                    if vt_dom_tuple[2] and vt_dom_tuple[4] is None
                    else None
                )
                vt_dom_tuple = (
                    vt_dom_tuple[0],
                    vt_dom_tuple[1],
                    vt_dom_parsed,
                    vt_dom_tuple[3],
                    vt_dom_tuple[4],
                )

                merged_ioc, merged_type, merged_data, merged_srcs, merged_error = merge_api_results(
                    vt_tuple, vt_dom_tuple
                )

        results_queue.put((merged_ioc, merged_type, merged_data, merged_srcs, merged_error))

    except Exception as exc:  # noqa: BLE001
        results_queue.put((ioc_str, None, None, [], str(exc)))


def fetch_and_parse_ioc_stonly(ioc_str: str, results_queue: Queue) -> None:
    """
    urlscan-only worker with URL→domain/IP expansion (urlscan calls only).
    """
    try:
        ioc_type_val = validate_ioc(ioc_str)

        us_q: Queue = Queue()
        _get_us_client().query_ioc(ioc_str, ioc_type_val, us_q)
        st_tuple = _get_first_5tuple(us_q)

        merged_ioc, merged_type, merged_data, merged_srcs, merged_error = st_tuple

        if ioc_type_val == "url":
            domain = urlparse(ioc_str).netloc.split(":")[0]
            if domain:
                ip_re = r"^(?:\d{1,3}\.){3}\d{1,3}$"
                us_dom_q: Queue = Queue()
                if re.match(ip_re, domain):
                    _get_us_client().query_ioc(domain, "ip_address", us_dom_q)
                else:
                    _get_us_client().query_ioc(domain, "domain", us_dom_q)
                us_dom_tuple = _get_first_5tuple(us_dom_q)

                merged_ioc, merged_type, merged_data, merged_srcs, merged_error = merge_api_results(
                    st_tuple, us_dom_tuple
                )

        results_queue.put((merged_ioc, merged_type, merged_data, merged_srcs, merged_error))

    except Exception as exc: 
        results_queue.put((ioc_str, None, None, [], str(exc)))


def fetch_and_parse_ioc_validinonly(ioc_str: str, results_queue: Queue) -> None:
    """
    Calls Validin **only** (domain/IP).
    """
    try:
        ioc_type_val = validate_ioc(ioc_str)

        if ioc_type_val == "domain":
            q = Queue()
            query_validin_domain(ioc_str, q)
            results_queue.put(q.get())
        elif ioc_type_val == "ip_address":
            q = Queue()
            query_validin_ip(ioc_str, q)
            results_queue.put(q.get())
        else:
            results_queue.put(
                (ioc_str, ioc_type_val, None, [], "Validin only supports domain or IP IOCs")
            )
    except Exception as exc:  # noqa: BLE001
        results_queue.put((ioc_str, None, None, [], str(exc)))


# ---------------------------------------------------------------------------#
# 4)  Batch helpers
# ---------------------------------------------------------------------------#
def process_iocs(ioc_iterable, results_queue: Queue) -> None:
    for ioc_str in ioc_iterable:
        fetch_and_parse_ioc(ioc_str, results_queue)


def process_iocs_with_selective_apis(
    ioc_iterable: list,
    use_vt: bool,
    use_us: bool,
    use_validin: bool,
    results_queue: queue.Queue,
):
    """
    Processes a list of IOCs using the specified APIs. If an IOC is a URL,
    it automatically extracts the domain/IP, queries it, and adds the
    results to be merged.
    """
    for ioc_str in ioc_iterable:
        try:
            ioc_type = validate_ioc(ioc_str)
        except ValueError as exc:
            results_queue.put((ioc_str, None, None, [], str(exc)))
            continue

        partials: List[Tuple[str, str, dict | None, List[str], str | None]] = []

        # --- Step 1: Query the primary ioc with individual error handling ---

        if use_vt:
            try:
                vt_q = Queue()
                _get_vt_client().query_ioc(ioc_str, ioc_type, vt_q)
                vt_tup = _get_first_5tuple(vt_q)
                vt_parsed = (
                    parse_virustotal_response(vt_tup[2], vt_tup[1])
                    if vt_tup[2] and vt_tup[4] is None
                    else None
                )
                partials.append((vt_tup[0], vt_tup[1], vt_parsed, vt_tup[3], vt_tup[4]))
            except Exception as e:
                # If VT fails, record the error tuple and continue
                partials.append((ioc_str, ioc_type, None, ["VirusTotal API"], f"VirusTotal Error: {e}"))

        if use_us:
            try:
                us_q = Queue()
                _get_us_client().query_ioc(ioc_str, ioc_type, us_q)
                partials.append(_get_first_5tuple(us_q))
            except Exception as e:
                # If urlscan fails, record the error tuple and continue
                partials.append((ioc_str, ioc_type, None, ["SecurityTrails API"], f"urlscan.io Error: {e}"))

        if use_validin and ioc_type in ("domain", "ip_address"):
            try:
                vq = Queue()
                (query_validin_domain if ioc_type == "domain" else query_validin_ip)(
                    ioc_str, vq
                )
                partials.append(_get_first_5tuple(vq))
            except Exception as e:
                 # If Validin fails, record the error tuple and continue
                partials.append((ioc_str, ioc_type, None, ["Validin API"], f"Validin Error: {e}"))

        # --- Step 2: If it's a URL, query the extracted hostname ---
        if ioc_type == "url":
            try:
                hostname = urlparse(ioc_str).hostname
                if hostname:
                    related_ioc_type = validate_ioc(hostname)
                    if use_vt:
                        piv_vt_q = Queue()
                        _get_vt_client().query_ioc(hostname, related_ioc_type, piv_vt_q)
                        piv_vt_tup = _get_first_5tuple(piv_vt_q)
                        piv_vt_parsed = (
                            parse_virustotal_response(piv_vt_tup[2], piv_vt_tup[1])
                            if piv_vt_tup[2] and piv_vt_tup[4] is None
                            else None
                        )
                        partials.append((piv_vt_tup[0], piv_vt_tup[1], piv_vt_parsed, piv_vt_tup[3], piv_vt_tup[4]))
                    if use_validin:
                        piv_val_q = Queue()
                        (query_validin_domain if related_ioc_type == "domain" else query_validin_ip)(hostname, piv_val_q)
                        partials.append(_get_first_5tuple(piv_val_q))
            except Exception as e:
                print(f"Error during URL pivot for '{ioc_str}': {e}")


        # --- Step 3: Merge ALL collected results (primary + pivoted) ---
        if not partials:
            results_queue.put(
                (ioc_str, ioc_type, None, [], "No APIs selected or an error occurred.")
            )
            continue
        
        # The merge function combines successful data and aggregates errors from the partials list
        merged = merge_api_results(ioc_str, *partials)
        results_queue.put(merged)
