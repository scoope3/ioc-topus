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
from ioc_topus.api.validin import (
    query_validin_domain, 
    query_validin_ip, 
    query_validin_hash,
    query_validin_domain_dns_history,
    query_validin_domain_osint_context,
    query_validin_domain_osint_history,
    query_validin_domain_dns_extra,
    query_validin_domain_crawl_history,
    query_validin_ip_dns_history,      
    query_validin_ip_dns_extra,      
    query_validin_ip_osint_history,    
    query_validin_ip_osint_context,   
    query_validin_ip_crawl_history
)

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
    Calls Validin **only** (domain/IP/fingerprint_hash).
    """
    try:
        ioc_type_val = validate_ioc(ioc_str)

        if ioc_type_val == "domain":
            # Create a temporary queue for each API call
            results = []
            
            # Original pivots query
            q1 = Queue()
            query_validin_domain(ioc_str, q1)
            results.append(q1.get())
            
            # DNS History
            q2 = Queue()
            query_validin_domain_dns_history(ioc_str, q2)
            results.append(q2.get())
            
            # OSINT Context
            q3 = Queue()
            query_validin_domain_osint_context(ioc_str, q3)
            results.append(q3.get())
            
            # OSINT History
            q4 = Queue()
            query_validin_domain_osint_history(ioc_str, q4)
            results.append(q4.get())
            
            # DNS Extra
            q5 = Queue()
            query_validin_domain_dns_extra(ioc_str, q5)
            results.append(q5.get())
            
            # Merge all results
            merged = merge_api_results(ioc_str, *results)
            results_queue.put(merged)
            
        elif ioc_type_val == "ip_address":
            q = Queue()
            query_validin_ip(ioc_str, q)
            results_queue.put(q.get())
        elif ioc_type_val in ("fingerprint_hash", "file_hash"):
            q = Queue()
            query_validin_hash(ioc_str, q)
            results_queue.put(q.get())
        else:
            results_queue.put(
                (ioc_str, ioc_type_val, None, [], "Validin only supports domain, IP, or hash IOCs")
            )
    except Exception as exc:
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
    delay_seconds: float = 0
):
    """
    Processes a list of IOCs using the specified APIs. If an IOC is a URL,
    it automatically extracts the domain/IP, queries it, and adds the
    results to be merged.
    """
    for ioc_str in ioc_iterable:
        original_ioc_str = str(ioc_str).strip()
        
        print(f"DEBUG process_iocs: Starting with IOC = '{original_ioc_str}'")
        
        try:
            ioc_type = validate_ioc(original_ioc_str)
        except ValueError as exc:
            results_queue.put((original_ioc_str, None, None, [], str(exc)))
            continue

        partials: List[Tuple[str, str, dict | None, List[str], str | None]] = []

        # --- Step 1: Query the primary ioc with individual error handling ---

        if use_vt:
            try:
                vt_q = Queue()
                _get_vt_client().query_ioc(original_ioc_str, ioc_type, vt_q)
                vt_tup = _get_first_5tuple(vt_q)
                
                # Validate the IOC in the tuple
                if vt_tup[0] != original_ioc_str:
                    print(f"WARNING: VT changed IOC from '{original_ioc_str}' to '{vt_tup[0]}'")
                    # Force it back
                    vt_tup = (original_ioc_str, vt_tup[1], vt_tup[2], vt_tup[3], vt_tup[4])
                
                vt_parsed = (
                    parse_virustotal_response(vt_tup[2], vt_tup[1])
                    if vt_tup[2] and vt_tup[4] is None
                    else None
                )
                partials.append((vt_tup[0], vt_tup[1], vt_parsed, vt_tup[3], vt_tup[4]))
            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg:
                    error_msg = "VirusTotal Error: API rate limit exceeded (no remaining quota)"
                else:
                    error_msg = f"VirusTotal Error: {e}"
                # Don't include source when there's an error and no data
                partials.append((original_ioc_str, ioc_type, None, [], error_msg))  # Empty sources list

        if use_us:
            try:
                us_q = Queue()
                _get_us_client().query_ioc(original_ioc_str, ioc_type, us_q)
                us_tup = _get_first_5tuple(us_q)
                
                # Validate the IOC in the tuple
                if us_tup[0] != original_ioc_str:
                    print(f"WARNING: URLScan changed IOC from '{original_ioc_str}' to '{us_tup[0]}'")
                    # Force it back
                    us_tup = (original_ioc_str, us_tup[1], us_tup[2], us_tup[3], us_tup[4])
                
                partials.append(us_tup)
            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg:
                    error_msg = "URLScan.io Error: API rate limit exceeded (no remaining quota)"
                else:
                    error_msg = f"URLScan.io Error: {e}"
                partials.append((original_ioc_str, ioc_type, None, [], error_msg))  # Empty sources list

        if use_validin and ioc_type in ("domain", "ip_address", "fingerprint_hash", "file_hash"):
            try:
                # A list to hold all the tuples from the various Validin API calls
                validin_results = []

                if ioc_type == "domain":
                    # List of all domain-specific functions to call
                    domain_functions = [
                        query_validin_domain,
                        query_validin_domain_dns_history,
                        query_validin_domain_osint_context,
                        query_validin_domain_osint_history,
                        query_validin_domain_dns_extra,
                        query_validin_domain_crawl_history, # New functionality
                    ]
                    # Call each function and add its result to our list
                    for func in domain_functions:
                        q = Queue()
                        # NOTE: The Validin functions in validin.py need to be updated
                        # to accept the API key directly if they don't already.
                        # Assuming they are modified to work like VT and US clients.
                        # If they still read from env, this call is fine.
                        func(original_ioc_str, q)
                        validin_results.append(_get_first_5tuple(q))

                elif ioc_type == "ip_address":
                    # List of all IP-specific functions to call
                    ip_functions = [
                        query_validin_ip,
                        query_validin_ip_dns_history,       # New functionality
                        query_validin_ip_dns_extra,         # New functionality
                        query_validin_ip_osint_history,     # New functionality
                        query_validin_ip_osint_context,     # New functionality
                        query_validin_ip_crawl_history      # New functionality
                    ]
                    # Call each function and add its result to our list
                    for func in ip_functions:
                        q = Queue()
                        func(original_ioc_str, q)
                        validin_results.append(_get_first_5tuple(q))

                elif ioc_type in ("fingerprint_hash", "file_hash"):
                    q = Queue()
                    query_validin_hash(original_ioc_str, q)
                    validin_results.append(_get_first_5tuple(q))

                # Add all the collected Validin results to the main partials list for merging
                partials.extend(validin_results)

            except Exception as e:
                error_msg = f"Validin Error: {e}"
                partials.append((original_ioc_str, ioc_type, None, [], error_msg))

        # --- Step 2: If it's a URL, query the extracted hostname ---
        if ioc_type == "url":
            try:
                hostname = urlparse(original_ioc_str).hostname
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
                print(f"Error during URL pivot for '{original_ioc_str}': {e}")

        # --- Step 3: Merge ALL collected results (primary + pivoted) ---
        if not partials:
            results_queue.put(
                (original_ioc_str, ioc_type, None, [], "No APIs selected or an error occurred.")
            )
            continue
        
        merged = merge_api_results(original_ioc_str, *partials)
        
        # Final validation
        if merged[0] != original_ioc_str:
            print(f"ERROR: Merge corrupted IOC from '{original_ioc_str}' to '{merged[0]}'")
            merged = (original_ioc_str, merged[1], merged[2], merged[3], merged[4])
        
        print(f"DEBUG process_iocs: Final result IOC = '{merged[0]}'")
        
        results_queue.put(merged)
        if delay_seconds > 0:
            time.sleep(delay_seconds)