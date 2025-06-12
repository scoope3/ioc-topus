"""
ioc_topus.utils.parsing
~~~~~~~~~~~~~~~~~~~~~~~
Pure-logic helpers for pulling useful information out of
urlscan / VirusTotal JSON blobs.   No network, no GUI imports.

Exports
-------
parse_res_data_requests
parse_res_meta_download_data
parse_res_meta_wappa_data
parse_filelike_attributes
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from ioc_topus.core.ioc import IOC
import json
import re
from typing import Any, Dict, List



# ---------------------------------------------------------------------------#
#  Helper: drop keys whose value is None / "" / [] / {}
# ---------------------------------------------------------------------------#
def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of *d* without empty / falsey values (except 0 / False)."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


# ---------------------------------------------------------------------------#
#  1)  urlscan “requests” → flattened list
# ---------------------------------------------------------------------------#
def parse_res_data_requests(req_list: Any) -> List[Dict[str, Any]]:
    """
    Flatten the ``"requests"`` array of a urlscan (or similar) capture.

    Parameters
    ----------
    req_list : list[dict] | Any
        The raw ``result["data"]["requests"]`` array.

    Returns
    -------
    list[dict]
        One dict per request with keys prefixed ``response_*``.
    """
    if not isinstance(req_list, list):
        return []

    parsed: List[Dict[str, Any]] = []
    for item in req_list:
        resp = item.get("response", {})             # NB: only one level
        flattened = _compact(
            {
                "response_url": resp.get("url"),
                "response_status": resp.get("status"),
                "response_statusText": resp.get("statusText"),
                "response_headers": resp.get("headers"),
                "response_mimeType": resp.get("mimeType"),
                "response_charset": resp.get("charset"),
                "response_remoteIPAddress": resp.get("remoteIPAddress"),
                "response_remotePort": resp.get("remotePort"),
                "response_protocol": resp.get("protocol"),
                "response_securityState": resp.get("securityState"),
                "response_securityDetails": resp.get("securityDetails"),
                "response_encodedDataLength": resp.get("encodedDataLength"),
                "response_dataLength": resp.get("dataLength"),
                "response_type": resp.get("type"),
                "response_requestId": resp.get("requestId"),
                "response_hash": resp.get("hash"),
                "response_size": resp.get("size"),
                "response_asn": resp.get("asn"),
                "response_geoip": resp.get("geoip"),
            }
        )
        if flattened:
            parsed.append(flattened)
    return parsed


# ---------------------------------------------------------------------------#
#  2)  urlscan “download” processor
# ---------------------------------------------------------------------------#
def parse_res_meta_download_data(dl_list: Any) -> List[Dict[str, Any]]:
    """
    Extract basic file info from the ``"download"`` subsection.

    Returns one dict per downloaded artefact.
    """
    if not isinstance(dl_list, list):
        return []

    return [
        _compact(
            {
                "downloaded_filename": f.get("filename"),
                "downloaded_filesize": f.get("filesize"),
                "downloaded_file_mimeType": f.get("mimeType"),
                "downloaded_sha256": f.get("sha256"),
                "downloaded_file_receivedBytes": f.get("receivedBytes"),
            }
        )
        for f in dl_list
    ]


# ---------------------------------------------------------------------------#
#  3)  urlscan “wappa” (Wappalyzer) processor
# ---------------------------------------------------------------------------#
def parse_res_meta_wappa_data(wappa_list: Any) -> List[Dict[str, Any]]:
    """
    Extract technology fingerprints from Wappalyzer results.
    """
    if not isinstance(wappa_list, list):
        return []

    return [
        _compact(
            {
                "wappalyzer_app_name": tech.get("app"),
                "wappalyzer_categories": [
                    c.get("name") for c in tech.get("categories", []) if c.get("name")
                ],
            }
        )
        for tech in wappa_list
    ]


# ---------------------------------------------------------------------------#
#  4)  VirusTotal “file” attributes (graphs / relationships)
# ---------------------------------------------------------------------------#
def parse_filelike_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Condense VT ``attributes`` from a file node into something lean.

    Returns
    -------
    dict
        With at minimum ``sha256`` plus any dynamic analysis summaries.
    """
    if not isinstance(attrs, dict):
        return {}

    file_parsed: Dict[str, Any] = _compact(
        {
            "sha256": attrs.get("sha256"),
            "names": attrs.get("names", []),
            "type_tag": attrs.get("type_tag"),
            "magic": attrs.get("magic"),
            "size": attrs.get("size"),
            "reputation": attrs.get("reputation"),
            "tlsh": attrs.get("tlsh"),
            "ssdeep": attrs.get("ssdeep"),
            "trid": attrs.get("trid", []),
        }
    )

    # -- sandbox verdicts ----------------------------------------------------
    sbv = attrs.get("sandbox_verdicts", {})
    if sbv:
        verdicts = []
        for ver in sbv.values():
            v = _compact(
                {
                    "sandbox_name": ver.get("sandbox_name"),
                    "category": ver.get("category"),
                    "malware_names": ver.get("malware_names", []),
                    "confidence": ver.get("confidence"),
                }
            )
            if v:
                verdicts.append(v)
        if verdicts:
            file_parsed.setdefault("dynamic_analysis", {})[
                "sandbox_verdicts"
            ] = verdicts

    # -- sigma analysis ------------------------------------------------------
    sigma = attrs.get("sigma_analysis_results", [])
    if sigma:
        simplified_sigma = [
            _compact(
                {
                    "rule_name": s.get("rule_name"),
                    "rule_level": s.get("rule_level"),
                    "rule_id": s.get("rule_id"),
                    "match_context": json.dumps(s.get("match_context"), indent=2),
                }
            )
            for s in sigma
        ]
        if simplified_sigma:
            file_parsed.setdefault("dynamic_analysis", {})[
                "sigma_analysis_results"
            ] = simplified_sigma

    # -- crowdsourced IDS ----------------------------------------------------
    csc = attrs.get("crowdsourced_ids_results", [])
    if csc:
        file_parsed.setdefault("dynamic_analysis", {})[
            "crowdsourced_ids_results"
        ] = csc

    return file_parsed


# ---------------------------------------------------------------------------#
#  Public exports
# ---------------------------------------------------------------------------#
__all__ = [
    "parse_res_data_requests",
    "parse_res_meta_download_data",
    "parse_res_meta_wappa_data",
    "parse_filelike_attributes",
]
