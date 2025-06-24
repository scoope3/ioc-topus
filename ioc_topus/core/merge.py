"""
ioc_topus.core.merge
~~~~~~~~~~~~~~~~~~~~
Utility to combine the tuples returned by multiple API threads into
one canonical result:

    (ioc, ioc_type, merged_data_dict, merged_sources, merged_error)

Rules
-----
1. A *falsey* / empty value NEVER overwrites a non-empty one.
2. Dict-valued keys are merged deeply (so VT "relationships" aren't
   wiped out by a later provider that returns `{}`).
3. `sources` are deduplicated.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple, TypedDict

MergedResult = Tuple[str, str, Dict[str, Any], List[str], str | None]


def _deep_merge(dest: Dict[str, Any], src: Dict[str, Any]) -> None:
    """
    Recursive dict merge. Non-empty `src` values win.
    """
    for key, val in src.items():
        # Correctly check for empty values, preserving 0 as a valid value.
        if val in (None, "", [], {}):
            continue

        if (
            key in dest
            and isinstance(dest.get(key), dict)
            and isinstance(val, dict)
        ):
            _deep_merge(dest[key], val)
        else:
            dest[key] = val


def merge_api_results(
    primary_ioc_str: str,
    *api_tuples: Tuple[str, str, dict | None, List[str], str | None]
) -> Tuple[str, str, dict, List[str], str | None]:
    """
    Merges a variable number of 5-tuples from different API calls.

    It intelligently layers data, prioritizing results from the primary IOC
    (e.g., for urlscan results) while using pivoted data for enrichment
    (e.g., for WHOIS from a domain).

    Args:
        primary_ioc_str: The original IOC submitted by the investigator.
        *api_tuples: A variable number of 5-tuples, each representing
                     an API result for either the primary or pivoted IOC.
    """
    if not isinstance(primary_ioc_str, str):
        print(f"WARNING: primary_ioc_str is not a string: {type(primary_ioc_str)} = {primary_ioc_str}")
        # Try to extract a string value
        if isinstance(primary_ioc_str, dict):
            if 'url' in primary_ioc_str:
                primary_ioc_str = primary_ioc_str['url']
            elif 'value' in primary_ioc_str:
                primary_ioc_str = primary_ioc_str['value']
            else:
                primary_ioc_str = str(primary_ioc_str)
        else:
            primary_ioc_str = str(primary_ioc_str)
    
    # Store the clean IOC
    clean_ioc_str = str(primary_ioc_str).strip()
    
    final_data = {}
    all_sources = set()
    all_errors = []

    # Separate primary results from pivoted results
    primary_results = []
    pivoted_results = []
    for tup in api_tuples:
        # Validate tuple structure
        if not isinstance(tup, tuple) or len(tup) < 5:
            print(f"WARNING: Invalid tuple in api_tuples: {tup}")
            continue
            
        # tup[0] is the ioc value from that specific API call
        if tup[0] == clean_ioc_str:
            primary_results.append(tup)
        else:
            pivoted_results.append(tup)

    # --- Step 1: Layer all pivoted data first to form a base ---
    for _, _, data_dict, sources, err in pivoted_results:
        if data_dict:
            final_data.update(data_dict)
        if sources:
            all_sources.update(sources)
        if err:
            all_errors.append(err)

    # --- Step 2: Layer primary data on top ---
    primary_ioc_type = None
    for _, ioc_type, data_dict, sources, err in primary_results:
        if ioc_type:
            primary_ioc_type = ioc_type
        if data_dict:
            final_data.update(data_dict)
        if sources:
            all_sources.update(sources)
        if err:
            all_errors.append(err)

    if not primary_ioc_type and api_tuples:
        primary_ioc_type = api_tuples[0][1]

    final_error_str = " | ".join(all_errors) if all_errors else None

    return (
        clean_ioc_str, 
        primary_ioc_type or "unknown",
        final_data,
        sorted(list(all_sources)),
        final_error_str,
    )