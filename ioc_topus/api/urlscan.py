"""
ioc_topus.api.urlscan
~~~~~~~~~~~~~~~~~~~~~
Light wrapper around urlscan.io (a SecurityTrails product).

Public interface
----------------
    UrlscanClient
        • query_ioc(...)                ← main entry (like VirusTotalClient.query_ioc)
        • query_domain_for_url(...)
        • search_domain(...)

The returned tuple shape matches the old code so the GUI/processor
need *no* further changes.

This module depends only on:
    - requests
    - stdlib
    - ioc_topus.utils.*
    - ioc_topus.config
No Tkinter!
"""

from __future__ import annotations

import json
import logging
import re
import time
from queue import Queue
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

from ioc_topus.config import URLSCAN_API_KEY
from ioc_topus.utils.helpers import (
    escape_ip,
    parse_url_for_queries,
)
from ioc_topus.utils.parsing import (
    parse_res_data_requests,
    parse_res_meta_download_data,
    parse_res_meta_wappa_data,
)

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------#
#  0) API Client
# ---------------------------------------------------------------------------#
class UrlscanClient:
    SEARCH_ENDPOINT = "https://urlscan.io/api/v1/search/"
    RESULT_ENDPOINT = "https://urlscan.io/api/v1/result/"

    def __init__(self, api_key: str | None = None, *, session: requests.Session | None = None) -> None:
        if api_key is None:
            api_key = URLSCAN_API_KEY
        if not api_key:
            raise RuntimeError("urlscan (SecurityTrails) API key missing (set .env or pass explicitly)")

        self.headers = {
            "API-Key": api_key,
            "Content-Type": "application/json",
        }
        self._session = session or requests.Session()

    # ------------------------------------------------------------------#
    # 1)  High-level IOC fetcher (public)
    # ------------------------------------------------------------------#
    def query_ioc(
        self,
        ioc: str,
        ioc_type: str,
        results_queue: Queue | None = None,
    ) -> Tuple[str, str, Dict[str, Any] | None, List[str], str | None]:
        """
        Mirrors the VirusTotalClient output tuple:
        (ioc, ioc_type, {"securitytrails_sections": …} OR None,
         ["SecurityTrails API"], error_or_None)
        """
        try:
            query_str = self._ioc_to_query(ioc, ioc_type)
        except ValueError as exc:
            return self._emit(ioc, ioc_type, None, str(exc), results_queue)

        # -----------------------------------------------------------#
        # (1) /search
        # -----------------------------------------------------------#
        try:
            found_items = self._search(query_str, max_results=100)
        except requests.HTTPError as exc:
            return self._emit(ioc, ioc_type, None, f"HTTPError: {exc}", results_queue)

        if not found_items:
            no_data = {"urlscan results": f"No SecurityTrails results for query '{query_str}'"}
            return self._emit(ioc, ioc_type, no_data, None, results_queue)

        # -----------------------------------------------------------#
        # (2) collect detail JSON for top N scans
        # -----------------------------------------------------------#
        all_downloaded_artifacts: Dict[str, Dict[str, Any]] = {}
        all_contacted_network: List[Dict[str, Any]] = []
        all_webpage_analysis: List[Dict[str, Any]] = []
        all_urlscan_verdict: List[Dict[str, Any]] = []
        all_urlscan_http_resp: List[Dict[str, Any]] = []
        st_parsed: Dict[str, Any] = {}

        for idx, item in enumerate(found_items[:20]):
            scan_id = item.get("_id", "")
            detail_json = self._fetch_result(scan_id)
            item_data = self._build_scan_data(item, detail_json)

            # --- raw headers (first 2 scans) -----------------------
            if idx < 2:
                st_parsed.setdefault("all_raw_response_headers", []).extend(
                    item_data.get("raw_response_headers", [])
                )

            # --- downloaded files ----------------------------------
            for d in item_data.get("downloaded_data", []):
                d["scan_id"] = scan_id
                d["scan_date"] = item_data.get("scan_date", "")
                fname = d.get("downloaded_filename") or "NoFilename"
                all_downloaded_artifacts.setdefault(fname, d)

            # --- contacted indicators ------------------------------
            for ipval in item_data.get("contacted_ips", []) or []:
                all_contacted_network.append(
                    {"scan_id": scan_id, "scan_date": item_data.get("scan_date", ""), "indicator_type": "IP", "value": ipval}
                )
            for asnval in item_data.get("contacted_asns", []) or []:
                all_contacted_network.append(
                    {"scan_id": scan_id, "scan_date": item_data.get("scan_date", ""), "indicator_type": "ASN", "value": asnval}
                )
            for dval in item_data.get("contacted_domains", []) or []:
                all_contacted_network.append(
                    {"scan_id": scan_id, "scan_date": item_data.get("scan_date", ""), "indicator_type": "Domain", "value": dval}
                )

            # --- webpage analysis ----------------------------------
            all_webpage_analysis.append(
                {
                    "scan_id": scan_id,
                    "scan_date": item_data.get("scan_date", ""),
                    "webpage_ip": item_data.get("webpage_ip", ""),
                    "webpage_asn": item_data.get("webpage_asn", ""),
                    "webpage_asnname": item_data.get("webpage_asnname", ""),
                    "webpage_ptr": item_data.get("webpage_ptr", ""),
                    "webpage_status": item_data.get("webpage_status", ""),
                    "webpage_title": item_data.get("webpage_title", ""),
                    "subresource_datasize": item_data.get("subresource_datasize", ""),
                    "webpage_server": item_data.get("webpage_server", ""),
                    "webpage_mimeType": item_data.get("webpage_mimeType", ""),
                    "webpage_redirected": item_data.get("webpage_redirected", ""),
                    "http_server_headers": item_data.get("http_server_headers", []),
                    "wappa_app": item_data.get("wappa_app", []),
                }
            )

            # --- verdict -------------------------------------------
            all_urlscan_verdict.append(
                {
                    "scan_id": scan_id,
                    "urlscan_score": item_data.get("urlscan_score", ""),
                    "urlscan_categories": item_data.get("urlscan_categories", []),
                    "tasked_tags": item_data.get("tasked_tags", []),
                }
            )

            # --- HTTP response -------------------------------------
            all_urlscan_http_resp.append(
                {
                    "scan_id": scan_id,
                    "scan_date": item_data.get("scan_date", ""),
                    "webpage_tlsAgeDays": item_data.get("webpage_tlsAgeDays", ""),
                    "webpage_tlsIssuer": item_data.get("webpage_tlsIssuer", ""),
                    "webpage_tlsValidDays": item_data.get("webpage_tlsValidDays", ""),
                    "linkDomains": item_data.get("linkDomains", []),
                    "requested_urls": sorted(set(item_data.get("requested_urls", []))),
                    "http_response_certificates": item_data.get("http_response_certificates", []),
                    "http_response_body_hash_list": item_data.get("http_response_body_hash_list", []),
                }
            )

        # -- deduplicate contacted indicators -------------------------
        seen: set[tuple[str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for row in all_contacted_network:
            pair = (row["indicator_type"], row["value"])
            if pair not in seen:
                seen.add(pair)
                deduped.append(row)
        all_contacted_network = deduped

        # -- assemble -------------------------------------------------
        st_parsed["all_downloaded_data"] = list(all_downloaded_artifacts.values())
        st_parsed["all_contacted_network"] = all_contacted_network
        st_parsed["all_webpage_analysis"] = all_webpage_analysis
        st_parsed["all_urlscan_verdict"] = all_urlscan_verdict
        st_parsed["all_urlscan_http_response"] = all_urlscan_http_resp

        sections = self._build_sections(st_parsed)
        wrapped = {"securitytrails_sections": sections}
        return self._emit(ioc, ioc_type, wrapped, None, results_queue)

    # ------------------------------------------------------------------#
    # 2)  Convenience wrappers
    # ------------------------------------------------------------------#
    def query_domain_for_url(self, url_str: str, results_queue: Queue | None = None):
        """
        Extract domain from *url_str* and run query_ioc(..., "domain", …).
        """
        try:
            parsed = urlparse(url_str)
            domain = parsed.netloc.split(":")[0] if parsed.netloc else None
            if not domain:
                return self._emit(url_str, "domain", None, None, results_queue)
            return self.query_ioc(domain, "domain", results_queue)
        except Exception as exc:          # noqa: BLE001
            return self._emit(url_str, "domain", None, str(exc), results_queue)

    def search_domain(self, domain_str: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """
        Simple wrapper over urlscan /search for *domain_str*.
        Raises HTTPError upwards; caller decides UX.
        """
        query_str = f"domain:{domain_str}"
        return self._search(query_str, max_results=max_results)

    # ------------------------------------------------------------------#
    # 3)  Internals
    # ------------------------------------------------------------------#
    def _ioc_to_query(self, ioc: str, ioc_type: str) -> str:
        if ioc_type == "domain":
            return f"domain:{ioc}"
        if ioc_type == "ip_address":
            return f"ip:{escape_ip(ioc)}"
        if ioc_type == "file_hash":
            return f"files.sha256:{ioc}"
        if ioc_type == "url":
            queries = parse_url_for_queries(ioc)
            if not queries:
                raise ValueError("Could not build urlscan query from URL")
            return queries[0]
        raise ValueError(f"Unsupported IOC type {ioc_type}")

    # -- network helpers ---------------------------------------------
    def _search(self, query_str: str, *, max_results: int) -> List[Dict[str, Any]]:
        all_found: list[dict[str, Any]] = []
        has_more = True
        search_after = None

        while has_more and len(all_found) < max_results:
            params = {"q": query_str, "size": max_results}
            if search_after:
                params["search_after"] = search_after

            resp = self._session.get(self.SEARCH_ENDPOINT, headers=self.headers, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            if not results:
                break
            all_found.extend(results)

            has_more = data.get("has_more", False)
            if has_more:
                search_after = ",".join(str(x) for x in results[-1].get("sort", []))
        return all_found

    def _fetch_result(self, scan_id: str) -> Dict[str, Any]:
        try:
            r = self._session.get(f"{self.RESULT_ENDPOINT}{scan_id}/", headers=self.headers, timeout=20)
            return r.json() if r.status_code == 200 else {}
        except Exception:                 # noqa: BLE001
            return {}

    # -- per-scan transformer ----------------------------------------
    @staticmethod
    def _build_scan_data(first_item: Dict[str, Any], detail_json: Dict[str, Any]) -> Dict[str, Any]:
        res_page = detail_json.get("page", {})
        res_lists = detail_json.get("lists", {})
        res_data = detail_json.get("data", {})
        res_verdicts = detail_json.get("verdicts", {})
        urlscan_v = res_verdicts.get("urlscan", {})

        meta_info = detail_json.get("meta", {})
        processors = meta_info.get("processors", {})
        download_data = processors.get("download", {}).get("data", [])
        wappa_data = processors.get("wappa", {}).get("data", [])

        parsed_responses = parse_res_data_requests(res_data.get("requests", []))
        parsed_downloads = parse_res_meta_download_data(download_data)
        parsed_wappa = parse_res_meta_wappa_data(wappa_data)

        search_task = first_item.get("task", {})
        search_page = first_item.get("page", {})
        search_stats = first_item.get("stats", {})

        return {
            "scan_id": first_item.get("_id", ""),
            "search_query": first_item.get("query", ""),
            "scan_date": search_task.get("time"),
            "tasked_domain": search_task.get("domain"),
            "tasked_url": search_task.get("url"),
            "tasked_tags": search_task.get("tags"),
            "webpage_ip": search_page.get("ip"),
            "webpage_asn": search_page.get("asn"),
            "webpage_asnname": search_page.get("asnname"),
            "webpage_ptr": search_page.get("ptr"),
            "webpage_status": search_page.get("status"),
            "webpage_title": search_page.get("title"),
            "contacted_ips_count": search_stats.get("uniqIPs"),
            "subresource_datasize": search_stats.get("dataLength"),
            "webpage_server": res_page.get("server"),
            "webpage_mimeType": res_page.get("mimeType"),
            "webpage_redirected": res_page.get("redirected"),
            "webpage_tlsAgeDays": res_page.get("tlsAgeDays"),
            "webpage_tlsIssuer": res_page.get("tlsIssuer"),
            "webpage_tlsValidDays": res_page.get("tlsValidDays"),
            "contacted_ips": res_lists.get("ips"),
            "contacted_asns": res_lists.get("asns"),
            "contacted_domains": res_lists.get("domains"),
            "http_server_headers": res_lists.get("servers"),
            "requested_urls": res_lists.get("urls"),
            "linkDomains": res_lists.get("linkDomains"),
            "http_response_certificates": res_lists.get("certificates"),
            "http_response_body_hash_list": res_lists.get("hashes"),
            "urlscan_score": urlscan_v.get("score"),
            "urlscan_categories": urlscan_v.get("categories"),
            "raw_response_headers": parsed_responses,
            "downloaded_data": parsed_downloads,
            "wappa_app": parsed_wappa,
        }

    # -- final section builder ---------------------------------------
    @staticmethod
    def _build_sections(st_parsed: Dict[str, Any]) -> Dict[str, Any]:
        sections = {
            "urlscan Downloaded Files": {"downloaded_data": st_parsed.get("all_downloaded_data", [])},
            "urlscan Contacted Network Indicators": {"contacted_items": st_parsed.get("all_contacted_network", [])},
            "urlscan Webpage Analysis": {"analysis": st_parsed.get("all_webpage_analysis", [])},
            "urlscan Verdict": {"verdict_items": st_parsed.get("all_urlscan_verdict", [])},
            "urlscan HTTP Response": {"http_items": st_parsed.get("all_urlscan_http_response", [])},
        }
        if "all_raw_response_headers" in st_parsed:
            sections["urlscan response header"] = {
                "raw_header_items": st_parsed["all_raw_response_headers"]
            }
        return sections

    # -- tuple helper -------------------------------------------------
    @staticmethod
    def _emit(
        ioc: str,
        ioc_type: str,
        data: Dict[str, Any] | None,
        error: str | None,
        q: Queue | None,
    ):
        payload = (ioc, ioc_type, data, ["SecurityTrails API"], error)
        if q is not None:
            q.put(payload)
        return payload
