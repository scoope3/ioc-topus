"""
ioc_topus.api.virustotal
~~~~~~~~~~~~~~~~~~~~~~~~
Thin Python wrapper around VirusTotal v3.

Public interface
----------------
- VirusTotalClient              main class (instantiate once per key)
    • query_ioc(...)            fetch IOC + relationships + comments
    • fetch_file_behaviour(...) sandbox behaviour summary

- parse_virustotal_response(...)   pure-logic transformer (unchanged)
- parse_virustotal_whois(...)      WHOIS normaliser (unchanged)

"""

from __future__ import annotations

import base64
import json
import logging
import time
from queue import Queue
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
import requests

from ioc_topus.config import VT_API_KEY      # single source of truth
from ioc_topus.utils.helpers import convert_timestamp
from ioc_topus.utils.parsing import parse_filelike_attributes
from ioc_topus import config

LOGGER = logging.getLogger(__name__)

#: limits the “deep fetch” of communicating files
MAX_SECONDARY_FILE_FETCH: int = 20
_VT_CLIENT = None
RELATIONSHIPS_TO_FETCH: List[str] = [
    "comments",
    "contacted_urls",
    "contacted_ips",
    "contacted_domains",
    "communicating_files",
    "graphs",
    "referrer_files"
]


# ---------------------------------------------------------------------------#
#  0) Helper: request wrapper
# ---------------------------------------------------------------------------#
def _make_request(method: str, url: str, *, headers: Dict[str, str], **kw) -> requests.Response:  # noqa: D401
    """
    A very small wrapper so we can patch / instrument in tests.
    """
    method = method.upper()
    if method == "GET":
        resp = requests.get(url, headers=headers, **kw)
    elif method == "POST":
        resp = requests.post(url, headers=headers, **kw)
    else:
        raise ValueError(f"Unsupported HTTP method {method}")
    return resp

def fetch_vt_file_behaviour_summary(sha256: str):
    """Backwards-compatibility helper kept for the parser."""
    global _VT_CLIENT
    if _VT_CLIENT is None:
        _VT_CLIENT = VirusTotalClient()                        # pulls key from config
    return _VT_CLIENT.fetch_file_behaviour(sha256)
# ---------------------------------------------------------------------------#
#  1)  API Client
# ---------------------------------------------------------------------------#
class VirusTotalClient:
    """
    Instantiate **once** (per API key) and re-use for all VT calls.
    """

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None, *, request_fn=_make_request) -> None:
        if api_key is None:
            api_key = VT_API_KEY
        if not api_key:
            raise RuntimeError("VirusTotal API key missing (set .env or pass explicitly)")

        self.api_key: str = api_key
        self.headers: Dict[str, str] = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }
        # injectable for tests
        self._request = request_fn

    # ------------------------------------------------------------------#
    # 1.1  High-level “one IOC” fetcher (main entry used by queues)
    # ------------------------------------------------------------------#
    def query_ioc(
        self,
        ioc: str,
        ioc_type: str,
        results_queue: Queue | None = None,
    ) -> Tuple[str, str, Dict[str, Any] | None, List[str], str | None]:
        """
        Fetch the IOC, then optional relationships & comments.

        (ioc, ioc_type, full_dict_or_None, ["VirusTotal API"], error_or_None)

        If *results_queue* is supplied, the tuple is *put* onto it
        and also returned; otherwise only returned.
        """
        try:
            endpoint = self._ioc_to_endpoint(ioc, ioc_type)
        except ValueError as exc:
            return self._emit(ioc, ioc_type, None, str(exc), results_queue)

        # -----------------------------------------------------------#
        # (1) main object
        # -----------------------------------------------------------#
        try:
            resp = self._request("GET", endpoint, headers=self.headers, timeout=20)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            return self._emit(ioc, ioc_type, None, "VT API request timed out", results_queue)
        except requests.exceptions.HTTPError as http_err:
            code = resp.status_code
            if code == 404:
                return self._emit(ioc, ioc_type, None, None, results_queue)
            if code == 429:
                return self._emit(ioc, ioc_type, None, "VT quota exceeded (429)", results_queue)
            if code == 401:
                return self._emit(ioc, ioc_type, None, "VT authentication error (401)", results_queue)
            return self._emit(ioc, ioc_type, None, f"VT HTTP {code}: {http_err}", results_queue)
        except requests.exceptions.RequestException as req_err:
            return self._emit(ioc, ioc_type, None, f"VT network error: {req_err}", results_queue)

        try:
            top_json = resp.json()
        except json.JSONDecodeError:
            return self._emit(ioc, ioc_type, None, "VT returned invalid JSON", results_queue)

        main_data = top_json.get("data")
        if not isinstance(main_data, dict):
            # treat “nothing found” as *no error*
            return self._emit(ioc, ioc_type, None, None, results_queue)

        vt_full: Dict[str, Any] = {
            "attributes": main_data.get("attributes", {}),
            "relationships": {},
        }

        # -----------------------------------------------------------#
        # (2) fetch relationships – errors stored but not fatal
        # -----------------------------------------------------------#
        for rel in RELATIONSHIPS_TO_FETCH:
            url = f"{endpoint}/relationships/{rel}?limit=40" 
            try:
                rrel = self._request("GET", url, headers=self.headers, timeout=15)
                rrel.raise_for_status()
                
                rel_json_data = rrel.json()
                
                # Check for and follow the 'related' link if it exists
                # This is common for 'graphs' and other complex relationships
                related_link = rel_json_data.get("links", {}).get("related")
                if related_link:
                    LOGGER.debug(f"Following related link for {rel}: {related_link}")
                    # The self.headers should still be valid for this new request.
                    rrel_related = self._request("GET", related_link, headers=self.headers, timeout=20) # Increased timeout for potentially larger data
                    rrel_related.raise_for_status()
                    vt_full["relationships"][rel] = rrel_related.json() # Store the data from the 'related' link
                else:
                    vt_full["relationships"][rel] = rel_json_data # Store the original data

            except requests.exceptions.HTTPError:
                if rrel.status_code == 404:
                    vt_full["relationships"][f"{rel}_error"] = "Not found"
                elif rrel.status_code == 429:
                    vt_full["relationships"][f"{rel}_error"] = "VT quota exceeded (429)"
                    break
                else:
                    vt_full["relationships"][f"{rel}_error"] = f"HTTP {rrel.status_code}"
            except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
                vt_full["relationships"][f"{rel}_error"] = f"{type(exc).__name__}"
            finally:
                time.sleep(0.1)         # gentle rate-limit

        # -----------------------------------------------------------#
        # (3) fetch full comments (optional, not fatal)
        # -----------------------------------------------------------#
        comments = self._fetch_comments(endpoint, limit=10)
        if comments:
            vt_full["comments_full"] = comments

        return self._emit(ioc, ioc_type, vt_full, None, results_queue)

    # ------------------------------------------------------------------#
    # 1.2  Behaviour summary 
    # ------------------------------------------------------------------#
    def fetch_file_behaviour(self, file_sha256: str) -> Dict[str, Any]:
        """
        GET /files/{sha256}/behaviour_summary → dict  (or {})
        """
        if not file_sha256:
            return {}
        url = f"{self.BASE}/files/{file_sha256}/behaviour_summary"
        try:
            r = self._request("GET", url, headers=self.headers, timeout=20)
            if r.status_code == 200:
                return r.json()
            return {}
        except Exception as exc:          # noqa: BLE001
            LOGGER.warning("VT behaviour_summary fetch failed: %s", exc)
            return {}

    # ------------------------------------------------------------------#
    # 1.3  Internals
    # ------------------------------------------------------------------#
    def _ioc_to_endpoint(self, ioc: str, ioc_type: str) -> str:
        """
        Map (ioc, type) → full VT endpoint URL.
        Raises ValueError on unsupported type.
        """
        map_ = {
            "file_hash": "/files/",
            "ip_address": "/ip_addresses/",
            "domain": "/domains/",
            "url": "/urls/",
        }
        if ioc_type not in map_:
            raise ValueError(f"Unsupported IOC type {ioc_type!r}")

        if ioc_type == "url":
            encoded = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            return f"{self.BASE}/urls/{encoded}"
        return f"{self.BASE}{map_[ioc_type]}{ioc}"

    def _fetch_comments(self, base_endpoint: str, *, limit: int = 20) -> List[Dict[str, Any]]:
        url = f"{base_endpoint}/comments?limit={limit}"
        try:
            r = self._request("GET", url, headers=self.headers, timeout=15)
            r.raise_for_status()
            return r.json().get("data", [])
        except Exception:
            return []

    @staticmethod
    def _emit(
        ioc: str,
        ioc_type: str,
        data: Dict[str, Any] | None,
        error: str | None,
        q: Queue | None,
    ):
        payload = (ioc, ioc_type, data, ["VirusTotal API"], error)
        if q is not None:
            q.put(payload)
        return payload


# ---------------------------------------------------------------------------#
#  2)  Pure-logic helpers (unchanged except imports)
# ---------------------------------------------------------------------------#
def parse_virustotal_response(response, ioc_type):
    """
    Takes the top-level data from query_virustotal(...) and transforms
    it into a more structured 'enriched_data' dict with fields like:
      - 'reputation'
      - 'vendors_marked_malicious'
      - 'PE Metadata'
      - 'dynamic_analysis' (subfields for sandbox, sigma, crowdsourced)
      - 'last_dns_records'
      - 'last_http_response_headers'
      - etc.

    If the IOC is a file_hash, we also attempt to fetch the file's
    behaviour_summary via fetch_vt_file_behaviour_summary(...).

    Returns a dict with the enriched data. If there's no data or
    an unsupported type, returns {}.
    """
    if not response:
        return {}

    enriched_data = {}
    attributes = response.get("attributes", {})
    dynamic_analysis = {}


    # ----------------------------------------------------------------
    # FILE HASH
    # ----------------------------------------------------------------
    if ioc_type == "file_hash":
        # Basic file metadata
        enriched_data["names"] = attributes.get("names", [])
        detectiteasy = attributes.get("detectiteasy", {}).get("values", [])
        enriched_data["linkers"] = [
            {"name": item.get("name"), "type": item.get("type")}
            for item in detectiteasy if item.get("type") == "Linker"
        ]
        enriched_data["compilers"] = [
            {"name": item.get("name"), "type": item.get("type")}
            for item in detectiteasy if item.get("type") == "Compiler"
        ]
        enriched_data["tools"] = [
            {"name": item.get("name"), "type": item.get("type")}
            for item in detectiteasy if item.get("type") == "Tool"
        ]
        enriched_data["installers"] = [
            {"name": item.get("name"), "type": item.get("type")}
            for item in detectiteasy if item.get("type") == "Installer"
        ]
        if attributes.get("type_tag"):
            enriched_data["File Type"] = attributes["type_tag"]

        # More fields
        enriched_data["magic"] = attributes.get("magic")
        enriched_data["size"] = attributes.get("size")
        enriched_data["reputation"] = attributes.get("reputation")
        enriched_data["tlsh"] = attributes.get("tlsh")
        enriched_data["ssdeep"] = attributes.get("ssdeep")
        enriched_data["trid"] = attributes.get("trid", [])
        enriched_data["permhash"] = attributes.get("permhash")
        enriched_data["authentihash"] = attributes.get("authentihash")

        # PE Info
        pe_info = attributes.get("pe_info") # Get the dict or None
        if isinstance(pe_info, dict) and pe_info: # Check if it's a non-empty dict
            timestamp = pe_info.get("timestamp")
            ft = convert_timestamp(timestamp)
            pe_dict = {
                "Compilation Timestamp": ft,
                "imphash": pe_info.get("imphash"),
                "Machine Type": pe_info.get("machine_type"),
                "Entry Point": pe_info.get("entry_point"),
                "Rich PE Header Hash": pe_info.get("rich_pe_header_hash"),
            }
            pe_filtered = {k: v for k, v in pe_dict.items() if v}
            if pe_filtered:
                enriched_data["PE Metadata"] = pe_filtered

        # .NET Assembly
        dna = attributes.get("dot_net_assembly") # Get the dict or None
        if isinstance(dna, dict) and dna: # Check if it's a non-empty dict
            parsed_dna = {
                "entry_point_rva": dna.get("entry_point_rva"),
                "metadata_header_rva": dna.get("metadata_header_rva"),
                "assembly_name": dna.get("assembly_name"),
                "resources_va": dna.get("resources_va"),
                "assembly_flags": dna.get("assembly_flags"),
                "strongname_va": dna.get("strongname_va"),
                "entry_point_token": dna.get("entry_point_token"),
                "tables_rows_map": dna.get("tables_rows_map"),
            }
            filtered_dna = {k: v for k, v in parsed_dna.items() if v}
            if filtered_dna:
                enriched_data["Dot Net Assembly"] = filtered_dna

        # ELF Info
        elf_info = attributes.get("elf_info") # Get the dict or None
        if isinstance(elf_info, dict) and elf_info: # Check if it's a non-empty dict
            elf_header = elf_info.get("header", {})
            if isinstance(elf_header, dict) and any(elf_header.values()): # Check header itself
                enriched_data["elf_info_header"] = {k: v for k, v in elf_header.items() if v}
            # Also add telfhash check here if it's specific to ELF
            telfhash_val = attributes.get("telfhash")
            if telfhash_val:
                enriched_data["telfhash"] = telfhash_val

        packers = attributes.get("packers", {})
        if packers:
            enriched_data["packers"] = {k: v for k, v in packers.items() if v}

        # Last analysis results => how many engines flagged it
        la_results = attributes.get("last_analysis_results", {})
        total_vendors = len(la_results)
        malicious_count = sum(1 for r in la_results.values() if r.get("category") == "malicious")
        if total_vendors > 0:
            enriched_data["vendors_marked_malicious"] = f"{malicious_count}/{total_vendors}"

        # Timestamps
        for ts_key in ["first_seen_itw_date", "last_analysis_date"]:
            ts_val = attributes.get(ts_key)
            if ts_val:
                converted_str = convert_timestamp(ts_val)
                enriched_data[ts_key] = converted_str

        # Sandbox verdicts, sigma, crowdsourced => place in dynamic_analysis
        sbv = attributes.get("sandbox_verdicts", {})
        if sbv:
            dynamic_analysis["sandbox_verdicts"] = []
            for sbn, ver in sbv.items():
                dsv = {
                    "sandbox_name": ver.get("sandbox_name"),
                    "category": ver.get("category"),
                    "malware_names": ver.get("malware_names", []),
                    "confidence": ver.get("confidence"),
                }
                dsv = {k: v for k, v in dsv.items() if v}
                if dsv:
                    dynamic_analysis["sandbox_verdicts"].append(dsv)

        sigma_results = attributes.get("sigma_analysis_results", [])
        sigma_out = []
        for result in sigma_results:
            rule_level = result.get("rule_level")
            rule_id = result.get("rule_id")
            rule_title = result.get("rule_title")
            rule_desc = result.get("rule_description")
            rule_author = result.get("rule_author")

            match_context_data = []
            for ctx_item in result.get("match_context", []):
                ctx_vals = ctx_item.get("values", {})
                filtered_ctx = {}
                for fieldname in [
                    "OriginalFileName","Description","CommandLine","ParentCommandLine",
                    "Image","ParentImage","QueryResults","QueryName","EventID","query",
                    "DestinationHostname","DestinationIp","DestinationPort","ScriptBlockText",
                    "Path","TargetFilename","Details","EventType","TargetObject"
                ]:
                    if fieldname in ctx_vals and ctx_vals[fieldname]:
                        filtered_ctx[fieldname] = ctx_vals[fieldname]

                if filtered_ctx:
                    match_context_data.append(filtered_ctx)

            sigma_out.append({
                "rule_level": rule_level,
                "rule_id": rule_id,
                "rule_title": rule_title,
                "rule_description": rule_desc,
                "rule_author": rule_author,
                "match_context": match_context_data,
            })
        if sigma_out:
            dynamic_analysis["sigma_analysis_results"] = sigma_out

        crowdsourced_results = attributes.get("crowdsourced_ids_results", [])
        csc_out = []
        for result in crowdsourced_results:
            alert_ctx_list = []
            for ctx in result.get("alert_context", []):
                filtered_ctx = {
                    "src_ip": ctx.get("src_ip"),
                    "src_port": ctx.get("src_port"),
                    "dest_ip": ctx.get("dest_ip"),
                    "dest_port": ctx.get("dest_port"),
                    "ja3": ctx.get("ja3"),
                    "ja3s": ctx.get("ja3s"),
                    "hostname": ctx.get("hostname"),
                    "url": ctx.get("url"),
                }
                filtered_ctx = {k: v for k, v in filtered_ctx.items() if v}
                if filtered_ctx:
                    alert_ctx_list.append(filtered_ctx)

            csc_out.append({
                "rule_category": result.get("rule_category"),
                "alert_severity": result.get("alert_severity"),
                "rule_msg": result.get("rule_msg"),
                "rule_id": result.get("rule_id"),
                "rule_source": result.get("rule_source"),
                "rule_url": result.get("rule_url"),
                "rule_raw": result.get("rule_raw"),
                "rule_references": result.get("rule_references"),
                "alert_context": alert_ctx_list
            })
        if csc_out:
            dynamic_analysis["crowdsourced_ids_results"] = csc_out

        # Attempt to fetch the file's behaviour_summary
        file_sha256 = attributes.get("sha256")
        if file_sha256:
            vt_behavior = fetch_vt_file_behaviour_summary(file_sha256)
            if vt_behavior and isinstance(vt_behavior.get("data"), dict):
                enriched_data["vt_behaviour_summary"] = vt_behavior["data"] # Stores the RAW summary

                bh_data = vt_behavior["data"]
                # Step 1) gather top-level fields
                command_executions   = bh_data.get("command_executions", [])
                processes_tree       = bh_data.get("processes_tree", [])
                signature_matches    = bh_data.get("signature_matches", [])
                registry_keys_set    = bh_data.get("registry_keys_set", [])
                registry_keys_opened = bh_data.get("registry_keys_opened", [])
                files_dropped        = bh_data.get("files_dropped", [])
                memory_pattern_urls  = bh_data.get("memory_pattern_urls", [])
                dns_lookups          = bh_data.get("dns_lookups", [])
                ja3_digests          = bh_data.get("ja3_digests", [])
                ip_traffic           = bh_data.get("ip_traffic", [])
                services_started     = bh_data.get("services_started", [])
                files_written_summary= bh_data.get("files_written", []) 
                files_deleted_summary= bh_data.get("files_deleted", []) 
                http_conversations   = bh_data.get("http_conversations", [])
                mutexes_created      = bh_data.get("mutexes_created", [])
                calls_highlighted    = bh_data.get("calls_highlighted", [])
                # Step 2) flatten out “files_written” and “files_deleted”
                all_written = []
                all_deleted = []

                def recurse_process_tree(proc_list):
                    for p in proc_list:
                        pid = p.get("process_id","")
                        fw = p.get("files_written", [])
                        for fpath in fw:
                            all_written.append({"process_id": pid, "file_path": fpath})

                        fd = p.get("files_deleted", [])
                        for dpath in fd:
                            all_deleted.append({"process_id": pid, "file_path": dpath})

                        # Recurse children
                        children = p.get("children", [])
                        if children:
                            recurse_process_tree(children)

                recurse_process_tree(processes_tree)

                # Step 3) Build a dict
                behavior_details = {
                    "command_executions":   command_executions,
                    "processes_tree":       processes_tree,
                    "signature_matches":    signature_matches,
                    "files_written":        all_written,
                    "files_dropped":        files_dropped if files_dropped else all_deleted,
                    "registry_keys_set":    registry_keys_set,
                    "registry_keys_opened": registry_keys_opened,
                    "memory_pattern_urls":  memory_pattern_urls,
                    "dns_lookups":          dns_lookups,
                    "ja3_digests":          ja3_digests,
                    "ip_traffic":           ip_traffic,
                    "services_started":     services_started,
                    "files_written":        files_written_summary,
                    "files_deleted":        files_deleted_summary,
                    "http_conversations":   http_conversations,
                    "mutexes_created":      mutexes_created,
                    "calls_highlighted":    calls_highlighted
                }
                dynamic_analysis["behavior_summary_details"] = behavior_details
            else:
                dynamic_analysis["behavior_summary_details"] = {"message": "Behavior summary not available or failed to fetch."}
    # ----------------------------------------------------------------
    # IP ADDRESS
    # ----------------------------------------------------------------
    elif ioc_type == "ip_address":
        lhc = attributes.get("last_https_certificate", {})
        validity = lhc.get("validity", {})
        c_md = {
            "not_before": validity.get("not_before"),
            "not_after": validity.get("not_after"),
            "thumbprint_sha256": lhc.get("thumbprint_sha256"),
            "subject_alternative_name": ", ".join(lhc.get("extensions", {}).get("subject_alternative_name", [])),
            "subject_key_identifier": lhc.get("extensions", {}).get("subject_key_identifier"),
            "key_usage": ", ".join(lhc.get("extensions", {}).get("key_usage", [])),
            "organization": lhc.get("issuer", {}).get("O"),
            "serial_number": lhc.get("serial_number"),
        }
        c_md_filtered = {k: v for k, v in c_md.items() if v not in [None, "", []]}
        if c_md_filtered:
            enriched_data["last_http_response_headers"] = c_md_filtered

        whois_data = attributes.get("whois", "")
        rdap_metadata = {
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network"),
        }
        rdap_whois_details = ""
        if whois_data:
            rdap_whois_details += f"{whois_data}\n"
        for k, v in rdap_metadata.items():
            if v:
                rdap_whois_details += f"{k}: {v}\n"
        if rdap_whois_details.strip():
            enriched_data["WHOIS Details"] = rdap_whois_details.strip()

        la = attributes.get("last_analysis_results", {})
        if la:
            tv = len(la)
            mc = sum(1 for r in la.values() if r.get("category") == "malicious")
            if tv > 0:
                enriched_data["vendors_marked_malicious"] = f"{mc}/{tv}"

        enriched_data["jarm"] = attributes.get("jarm")
        enriched_data["reputation"] = attributes.get("reputation")

        # Add Last Analysis Date for IP
        lad_ip = attributes.get("last_analysis_date")
        if lad_ip:
            enriched_data["last_analysis_date"] = convert_timestamp(lad_ip)
        # Sandbox verdicts, sigma
        sbv = attributes.get("sandbox_verdicts", {})
        if sbv:
            dynamic_analysis["sandbox_verdicts"] = []
            for sbn, ver in sbv.items():
                dsv = {
                    "sandbox_name": ver.get("sandbox_name"),
                    "category": ver.get("category"),
                    "malware_names": ver.get("malware_names", []),
                    "confidence": ver.get("confidence"),
                }
                dsv = {k: v for k, v in dsv.items() if v}
                if dsv:
                    dynamic_analysis["sandbox_verdicts"].append(dsv)

        sigma = attributes.get("sigma_analysis_results", [])
        if sigma:
            simplified_sigma = []
            for sigma_result in sigma:
                simplified_result = {
                    "rule_name": sigma_result.get("rule_name"),
                    "rule_level": sigma_result.get("rule_level"),
                    "rule_id": sigma_result.get("rule_id"),
                    "match_context": json.dumps(sigma_result.get("match_context"), indent=2)
                }
                simplified_sigma.append(simplified_result)
            if simplified_sigma:
                dynamic_analysis["sigma_analysis_results"] = simplified_sigma

        csc = attributes.get("crowdsourced_ids_results", [])
        if csc:
            dynamic_analysis["crowdsourced_ids_results"] = csc

    # ----------------------------------------------------------------
    # DOMAIN
    # ----------------------------------------------------------------
    elif ioc_type == "domain":
        registrar = attributes.get("registrar")
        if registrar:
            enriched_data["registrar"] = registrar

        rep = attributes.get("reputation")
        if rep is not None:
            enriched_data["reputation"] = rep

        lad_domain = attributes.get("last_analysis_date")
        if lad_domain:
            enriched_data["last_analysis_date"] = convert_timestamp(lad_domain)
        whois_d = attributes.get("whois")
        if whois_d:
            enriched_data["WHOIS Details"] = whois_d

        c_sc = attributes.get("crowdsourced_context", [])
        dtls = [item.get("details") for item in c_sc if "details" in item and item.get("details")]
        if dtls:
            enriched_data["crowdsourced_context_details"] = dtls

        last_dns_records = attributes.get("last_dns_records", [])
        out_dn = []
        for record in last_dns_records:
            if record and any(record.values()):
                rname_val = record.get("rname") or "not applicable"
                out_dn.append({
                    "type": record.get("type"),
                    "ttl": record.get("ttl"),
                    "value": record.get("value"),
                    "rname": rname_val,
                })
        if out_dn:
            enriched_data["last_dns_records"] = out_dn

        jarm = attributes.get("jarm")
        if jarm:
            enriched_data["jarm"] = jarm

        lhc = attributes.get("last_https_certificate", {})
        extensions = lhc.get("extensions", {})
        validity = lhc.get("validity", {})
        cert_data = {
            "key_usage": extensions.get("key_usage", []),
            "extended_key_usage": extensions.get("extended_key_usage", []),
            "not_before": validity.get("not_before"),
            "not_after": validity.get("not_after"),
            "thumbprint_sha256": lhc.get("thumbprint_sha256"),
            "subject_key_identifier": extensions.get("subject_key_identifier"),
            "subject_alternative_name": extensions.get("subject_alternative_name", []),
        }
        cert_data = {k: v for k, v in cert_data.items() if v not in [None, "", [], {}]}

        issuer = lhc.get("issuer", {})
        issuer_org = issuer.get("O")
        if issuer_org:
            cert_data["issuer_organization"] = issuer_org

        if cert_data:
            enriched_data["last_http_response_headers"] = cert_data

        la = attributes.get("last_analysis_results", {})
        if la:
            tv = len(la)
            mc = sum(1 for r in la.values() if r.get("category") == "malicious")
            if tv > 0:
                enriched_data["vendors_marked_malicious"] = f"{mc}/{tv}"

        cats_domain = attributes.get("categories", {})
        if cats_domain:
            enriched_data["categories"] = {k: v for k, v in cats_domain.items()}
        sbv = attributes.get("sandbox_verdicts", {})
        if sbv:
            dynamic_analysis["sandbox_verdicts"] = []
            for sbn, ver in sbv.items():
                dsv = {
                    "sandbox_name": ver.get("sandbox_name"),
                    "category": ver.get("category"),
                    "malware_names": ver.get("malware_names", []),
                    "confidence": ver.get("confidence"),
                }
                dsv = {k: v for k, v in dsv.items() if v}
                if dsv:
                    dynamic_analysis["sandbox_verdicts"].append(dsv)

        sigma = attributes.get("sigma_analysis_results", [])
        if sigma:
            simplified_sigma = []
            for sigma_result in sigma:
                simplified_result = {
                    "rule_name": sigma_result.get("rule_name"),
                    "rule_level": sigma_result.get("rule_level"),
                    "rule_id": sigma_result.get("rule_id"),
                    "match_context": json.dumps(sigma_result.get("match_context"), indent=2)
                }
                simplified_sigma.append(simplified_result)
            if simplified_sigma:
                dynamic_analysis["sigma_analysis_results"] = simplified_sigma

        csc = attributes.get("crowdsourced_ids_results", [])
        if csc:
            dynamic_analysis["crowdsourced_ids_results"] = csc

    # ----------------------------------------------------------------
    # URL
    # ----------------------------------------------------------------
    elif ioc_type == "url":
        rep = attributes.get("reputation")
        if rep is not None:
            enriched_data["reputation"] = rep

        http_data = {}
        last_final_url = attributes.get("last_final_url")
        if last_final_url is not None:
            http_data["Last Final URL"] = last_final_url

        redchain = attributes.get("redirection_chain", [])
        if redchain:
            http_data["Redirection Chain"] = ", ".join(redchain)

        content_len = attributes.get("last_http_response_content_length")
        if content_len is not None:
            http_data["Last HTTP Response Content Length"] = content_len

        page_title = attributes.get("title")
        if page_title:
            http_data["Page Title"] = page_title

        http_code = attributes.get("last_http_response_code")
        if http_code is not None:
            http_data["Last HTTP Response Code"] = http_code

        # Possibly store certain known HTTP headers if present
        lhrh = attributes.get("last_http_response_headers", {})
        if lhrh:
            for hdr in [
                "Date",
                "Content-Type",
                "Report-To",
                "Vary",
                "Server",
                "Content-Encoding",
                "Referrer-Policy",
                "WWW-Authenticate",
                "Content-Length"
            ]:
                val = lhrh.get(hdr)
                if val is not None:
                    http_data[hdr] = val

        if http_data:
            enriched_data["http_response_data"] = http_data

        lad = attributes.get("last_analysis_date")
        if lad:
            conv = convert_timestamp(lad)
            enriched_data["last_analysis_date"] = conv

        la = attributes.get("last_analysis_results", {})
        if la:
            tv = len(la)
            mc = sum(1 for r in la.values() if r.get("category") == "malicious")
            if tv > 0:
                enriched_data["vendors_marked_malicious"] = f"{mc}/{tv}"

        cats = attributes.get("categories", {})
        if cats:
            enriched_data["categories"] = {k: v for k, v in cats.items()}

        out_links = attributes.get("outgoing_links", [])
        if out_links:
            enriched_data["outgoing_links"] = out_links

        sbv = attributes.get("sandbox_verdicts", {})
        if sbv:
            dynamic_analysis["sandbox_verdicts"] = []
            for sbn, ver in sbv.items():
                dsv = {
                    "sandbox_name": ver.get("sandbox_name"),
                    "category": ver.get("category"),
                    "malware_names": ver.get("malware_names", []),
                    "confidence": ver.get("confidence"),
                }
                dsv = {k: v for k, v in dsv.items() if v}
                if dsv:
                    dynamic_analysis["sandbox_verdicts"].append(dsv)

        sigma = attributes.get("sigma_analysis_results", [])
        if sigma:
            simplified_sigma = []
            for sigma_result in sigma:
                simplified_result = {
                    "rule_name": sigma_result.get("rule_name"),
                    "rule_level": sigma_result.get("rule_level"),
                    "rule_id": sigma_result.get("rule_id"),
                    "match_context": json.dumps(sigma_result.get("match_context"), indent=2)
                }
                simplified_sigma.append(simplified_result)
            if simplified_sigma:
                dynamic_analysis["sigma_analysis_results"] = simplified_sigma

        csc = attributes.get("crowdsourced_ids_results", [])
        if csc:
            dynamic_analysis["crowdsourced_ids_results"] = csc

    # ----------------------------------------------------------------
    # RELATIONSHIPS
    # ----------------------------------------------------------------
    relationships = response.get("relationships", {})
    if relationships:
        enriched_data["relationships"] = {}

        # (B) Graphs => Process data to get lists of IPs, Files, URLs
        graphs_data_from_relationship = relationships.get("graphs", {})
        # The actual list of nodes is under a 'data' key if the relationship returned a list of graph objects,
        # or directly if 'graphs' itself is the object with attributes.
        # Assuming the followed 'related' link provides the structure where graph_data_items are the actual graph objects.
        
        graph_data_items = graphs_data_from_relationship.get("data", [])
        if not isinstance(graph_data_items, list) and isinstance(graphs_data_from_relationship, dict) and "attributes" in graphs_data_from_relationship: # Handle single graph object
            graph_data_items = [graphs_data_from_relationship]
        elif not isinstance(graph_data_items, list) and isinstance(graphs_data_from_relationship, list): # If 'graphs' itself is a list of items
             graph_data_items = graphs_data_from_relationship


        parsed_graph_pivots = {"ip_address": set(), "file": [], "url": set()}
        seen_file_shas_in_graph = set()

        print(f"\n--- DEBUG PARSER: START NEW GRAPH CONTENT PROCESSING ---")
        print(f"DEBUG PARSER: Number of graph items to process: {len(graph_data_items)}")

        for graph_item in graph_data_items:
            if not isinstance(graph_item, dict):
                print(f"DEBUG PARSER: Skipping non-dict graph_item.")
                continue

            # Graph attributes might directly contain lists (less common for VT API v3 resolved graphs)
            # More commonly, nodes are within graph_item["attributes"]["nodes"]
            graph_attrs = graph_item.get("attributes", {})
            nodes_list = graph_attrs.get("nodes", [])

            if not isinstance(nodes_list, list):
                print(f"DEBUG PARSER: No 'nodes' list in graph_item attributes or it's not a list. Attrs keys: {list(graph_attrs.keys())}")
                # Fallback: check if graph_attrs itself has direct 'ip_address', 'url', 'file' keys (less likely for VT)
                direct_ips = graph_attrs.get("ip_address", [])
                if isinstance(direct_ips, list): parsed_graph_pivots["ip_address"].update(direct_ips)
                direct_urls = graph_attrs.get("url", [])
                if isinstance(direct_urls, list): parsed_graph_pivots["url"].update(direct_urls)
                direct_files = graph_attrs.get("file", []) # Expects list of dicts: [{"sha256": "...", "type_tag": "..."}]
                if isinstance(direct_files, list):
                    for file_entry in direct_files:
                        if isinstance(file_entry, dict):
                            sha = file_entry.get("sha256")
                            if sha and sha not in seen_file_shas_in_graph:
                                parsed_graph_pivots["file"].append(file_entry)
                                seen_file_shas_in_graph.add(sha)
                continue # Move to next graph_item if no nodes_list

            print(f"DEBUG PARSER: Processing {len(nodes_list)} nodes for a graph_item.")
            for node in nodes_list:
                if not isinstance(node, dict):
                    continue
                
                node_type = node.get("type")
                entity_id = node.get("entity_id", "").strip() # Often the main identifier (IP, domain, SHA256)
                text_val = node.get("text", "").strip()     # Often the display name or URL string
                node_attrs = node.get("entity_attributes", {}) # For additional info like type_tag for files

                if node_type == "ip_address" and entity_id:
                    parsed_graph_pivots["ip_address"].add(entity_id)
                elif node_type == "url" and text_val: # URLs often use 'text'
                    parsed_graph_pivots["url"].add(text_val)
                elif node_type == "domain" and entity_id: # Domains might use entity_id or text
                    parsed_graph_pivots["url"].add(entity_id) # Or add to a separate "domain" list if needed
                elif node_type == "file" and entity_id:
                    if entity_id not in seen_file_shas_in_graph:
                        file_info = {"sha256": entity_id}
                        type_tag = node_attrs.get("type_tag")
                        if type_tag:
                            file_info["type_tag"] = type_tag
                        # You could extend this to fetch more attributes for graph files if needed/available
                        parsed_graph_pivots["file"].append(file_info)
                        seen_file_shas_in_graph.add(entity_id)
        
        # Store the parsed graph pivots if any data was found
        final_graph_output = {}
        if parsed_graph_pivots["ip_address"]:
            final_graph_output["ip_address"] = sorted(list(parsed_graph_pivots["ip_address"]))
        if parsed_graph_pivots["file"]:
            final_graph_output["file"] = parsed_graph_pivots["file"] # Already a list of dicts
        if parsed_graph_pivots["url"]:
            final_graph_output["url"] = sorted(list(parsed_graph_pivots["url"]))

        if final_graph_output:
            enriched_data.setdefault("relationships", {})
            enriched_data["relationships"]["graphs"] = final_graph_output
            print(f"DEBUG PARSER: Assigned final_graph_output to enriched_data['relationships']['graphs']")
        
        print(f"--- DEBUG PARSER: END NEW GRAPH CONTENT PROCESSING ---")

        # (C) Communicating files => partial file data

        communicating_files_list = []
        if "communicating_files" in relationships:
            cf_data = relationships["communicating_files"].get("data", [])
            headers = {
                "accept": "application/json",
                "x-apikey": config.VT_API_KEY # Ensure VT_API_KEY_IN_USE is accessible
            }
            for i, item in enumerate(cf_data):
                if i >= MAX_SECONDARY_FILE_FETCH: # Respect the limit
                    break
                partial_file_attrs = item.get("attributes", {})
                partial_file = parse_filelike_attributes(partial_file_attrs) # Use existing helper
                file_id = item.get("id")

                if file_id:
                    # Attempt to fetch full details for the file
                    try:
                        file_details_url = f"https://www.virustotal.com/api/v3/files/{file_id}"
                        resp = requests.get(file_details_url, headers=headers, timeout=10) # Added timeout
                        time.sleep(0.1) # Small delay for rate limiting
                        if resp.status_code == 200:
                            file_data = resp.json()
                            full_attrs = file_data.get("data", {}).get("attributes", {})
                            if full_attrs:
                                full_parsed = parse_filelike_attributes(full_attrs)
                                # Combine partial and full, prioritizing full data
                                full_parsed.update(partial_file) # Update with partial if keys missing in full
                                full_parsed["sha256"] = file_id # Ensure sha256 is present
                                communicating_files_list.append(full_parsed)
                            else:
                                # If full fetch worked but no attributes, use partial
                                partial_file["sha256"] = file_id
                                communicating_files_list.append(partial_file)
                        else:
                            # Fetch failed, use partial data
                            partial_file["sha256"] = file_id
                            communicating_files_list.append(partial_file)
                    except Exception as comm_file_ex:
                        # Network or other error during fetch, use partial
                        # print(f"[!] Error fetching full details for communicating file {file_id}: {comm_file_ex}") # Optional debug print
                        partial_file["sha256"] = file_id
                        communicating_files_list.append(partial_file)
                else:
                    # No file ID available in the relationship data, use partial only
                    communicating_files_list.append(partial_file)
            # ---> START DEBUG PRINT 2 <---
            print(f"DEBUG: Processed 'communicating_files_list' in parser. Length: {len(communicating_files_list)}")
            if communicating_files_list:
                print(f"DEBUG: First item in communicating_files_list: {communicating_files_list[0]}")
            # ---> END DEBUG PRINT 2 <---
            # Store the processed list in the relationships dict if not empty
            if communicating_files_list:
                if "relationships" not in enriched_data:
                    enriched_data["relationships"] = {}
                enriched_data["relationships"]["Communicating Files"] = communicating_files_list
        # ---> END INSERT <---

        # (E) Referrer Files
        referrer_files_list = []
        if "referrer_files" in relationships:
            rf_data = relationships["referrer_files"].get("data", [])
            for item in rf_data:
                # The 'id' of a referrer_file item is often its SHA256 hash.
                # The 'attributes' are for the referrer file itself.
                file_id_from_item = item.get("id")
                referrer_file_attrs = item.get("attributes", {})
                
                if referrer_file_attrs: # Ensure there are attributes to parse
                    parsed_ref_file = parse_filelike_attributes(referrer_file_attrs)
                    
                    # Ensure sha256 is present, prefer 'id' if attributes don't list it or for consistency
                    if file_id_from_item and "sha256" not in parsed_ref_file:
                        parsed_ref_file["sha256"] = file_id_from_item
                    elif not parsed_ref_file.get("sha256") and file_id_from_item: # If sha256 in attrs is empty but id is not
                         parsed_ref_file["sha256"] = file_id_from_item
                    
                    if parsed_ref_file.get("sha256"): # Only add if we have an identifier
                        referrer_files_list.append(parsed_ref_file)
                    else:
                        print(f"DEBUG: Referrer file skipped, no SHA256 identifier. Attrs: {referrer_file_attrs}, ID: {file_id_from_item}")


            if referrer_files_list:
                enriched_data.setdefault("relationships", {}) # Ensure 'relationships' key exists
                enriched_data["relationships"]["Referrer Files"] = referrer_files_list
                print(f"DEBUG: Processed 'Referrer Files' in parser. Length: {len(referrer_files_list)}")
                if referrer_files_list:
                    print(f"DEBUG: First item in Referrer Files list: {referrer_files_list[0]}")

        # (D) Contacted items  ➜  keep each table separate
        contacted_urls   = []
        contacted_domains = []
        contacted_ips     = []

        # ---- 1. URLs ----
        if "contacted_urls" in relationships:
            for item in relationships["contacted_urls"].get("data", []):
                url_val = (
                    item.get("attributes", {}).get("last_final_url")      # preferred
                    or item.get("attributes", {}).get("url")             # fallback
                    or item.get("id", "")
                )
                if url_val:
                    contacted_urls.append(url_val)

        # ---- 2. Domains ----
        if "contacted_domains" in relationships:
            for item in relationships["contacted_domains"].get("data", []):
                dom_val = item.get("id", "")
                if dom_val:
                    contacted_domains.append(dom_val)

        # ---- 3. IPs ----
        if "contacted_ips" in relationships:
            for item in relationships["contacted_ips"].get("data", []):
                ip_val = item.get("id", "")
                if ip_val:
                    contacted_ips.append(ip_val)

        # ---- 4. Store results if non‑empty ----
        if any([contacted_urls, contacted_domains, contacted_ips]):
            enriched_data.setdefault("relationships", {})
        if contacted_urls:
            enriched_data["relationships"]["Contacted URLs"] = sorted(set(contacted_urls))
        if contacted_domains:
            enriched_data["relationships"]["Contacted Domains"] = sorted(set(contacted_domains))
        if contacted_ips:
            enriched_data["relationships"]["Contacted IPs"] = sorted(set(contacted_ips))






    # If we found any dynamic analysis fields, store them under "dynamic_analysis"
    if dynamic_analysis:
        enriched_data["dynamic_analysis"] = dynamic_analysis

    # Remove empty fields from the final output
    enriched_data = {k: v for k, v in enriched_data.items() if v not in [None, "", [], {}]}
        # ------------------------------------------------------------
    # COMMON SECTION ▸ VirusTotal comments
    # ------------------------------------------------------------
    comments_full = response.get("comments_full", [])
    if comments_full:
        rendered = []
        for c in comments_full:
            attrs = c.get("attributes", {})
            txt   = (attrs.get("text") or "").strip()
            if not txt:
                continue                # skip empty comments
            date  = convert_timestamp(attrs.get("date"))
            user  = attrs.get("user", {}).get("id")    # may be None
            hdr   = f"({date}) {user or ''}".strip()
            rendered.append(f"{hdr}\n{txt}")

        if rendered:                     # only add if at least one had text
            # single string, blank line + hr between entries
            enriched_data["vt_comments"] = "\n\n---\n".join(rendered)
    print(f"\nDEBUG PARSER: Final enriched_data['relationships'] before return:\n{json.dumps(enriched_data.get('relationships', {}), indent=2)}")
    return enriched_data


def parse_virustotal_whois(raw_whois_str: str) -> dict:
    """
    Parses the WHOIS string returned by VirusTotal (Community API) into
    a dict

    - If multiple lines appear for the same field (like 'Admin Country'),
      this function will try to pick the first real, non-"REDACTED" line.
    - Lines mentioning "REDACTED FOR PRIVACY" are skipped, so we only store
      a single best value for each key.
    - Domain Status lines are joined into a comma-separated single string.
    - All lines are matched case-insensitively; the final dictionary uses
      consistent keys such as "Administrative city", "Billing organization", etc.

    Returns:
        A dictionary of normalized WHOIS fields. Example keys include:
          "Create date", "Domain name", "Expiry date", "Name server 1",
          "DNSSEC", "Administrative city", "Billing organization", 
          "Registrant street", "Technical organization", etc.
    """

    # ------------------------------------------------------------------------
    # 1) A function to unify lines, ignoring repeated or privacy lines
    # ------------------------------------------------------------------------
    def normalize_value(val: str) -> str:
        """
        Strips extra spaces, checks for placeholders like 'REDACTED FOR PRIVACY'.
        Returns empty string if it's obviously privacy/redacted. Otherwise returns
        the trimmed string.
        """
        v = val.strip()
        if not v:
            return ""
        # If the line says something like 'REDACTED FOR PRIVACY' – skip it
        if "REDACTED FOR PRIVACY" in v.upper():
            return ""
        return v

    # This dictionary will hold the final results (one value per key).
    parsed = {}


    domain_status_list = []

    candidate_values = {}

    def store_once(field_name: str, raw_val: str):
        """ Store if 'raw_val' is real (non-empty, non-privacy).
        """
        v = normalize_value(raw_val)
        if not v:
            return
        # If candidate_values[field_name] is already set, don't overwrite
        if field_name not in candidate_values or not candidate_values[field_name]:
            candidate_values[field_name] = v

    # ------------------------------------------------------------------------
    # 2) A small mapper that yields (field_key, field_value) for recognized lines
    # ------------------------------------------------------------------------
    def line_to_keyval(line: str):
        """
        Identifies known fields by case-insensitive matching. Returns either:
           (some_key, some_value)
        or
           (None, None)
        if unrecognized or empty.
        """

        lower = line.lower()
        # It's typical: "Admin City: Reykjavik"
        if ':' not in line:
            return None, None

        left_side, right_side = line.split(':', 1)
        left_side = left_side.strip().lower()
        right_side = right_side.strip()

        # Domain-level
        if left_side.startswith("creation date") or left_side.startswith("create date"):
            return "Create date", right_side
        if left_side.startswith("domain name"):
            return "Domain name", right_side
        if left_side.startswith("domain registrar id"):
            return "Domain registrar id", right_side
        if left_side.startswith("domain registrar url"):
            return "Domain registrar url", right_side
        if left_side.startswith("expiry date") or left_side.startswith("registry expiry date"):
            return "Expiry date", right_side
        if left_side.startswith("dnssec"):
            return "DNSSEC", right_side
        if left_side.startswith("domain status"):
            return "Domain Status (multi)", right_side
        if left_side.startswith("name server"):
            # Some WHOIS might say "Name Server 1:", or repeated "Name Server:"
            # We handle them in a single approach: "Name server (multi)"
            return "Name server (multi)", right_side

        if left_side.startswith("update date") or left_side.startswith("updated date"):
            return "Update date", right_side
        if left_side.startswith("registrar abuse contact email"):
            return "Registrar Abuse Contact Email", right_side
        if left_side.startswith("registrar abuse contact phone"):
            return "Registrar Abuse Contact Phone", right_side
        if left_side.startswith("registrar iana id"):
            return "Registrar IANA ID", right_side
        if left_side.startswith("registrar url"):
            return "Registrar URL", right_side
        if left_side.startswith("registrar whois server"):
            return "Registrar WHOIS Server", right_side
        if left_side.startswith("registrar:"):
            return "Registrar", right_side
        if left_side.startswith("registrar domain id") or left_side.startswith("registry domain id"):
            return "Registrar Domain ID", right_side

        # Billing
        if left_side.startswith("billing city"):
            return "Billing city", right_side
        if left_side.startswith("billing country"):
            return "Billing country", right_side
        if left_side.startswith("billing organization"):
            return "Billing organization", right_side
        if left_side.startswith("billing postal code"):
            return "Billing postal code", right_side
        if left_side.startswith("billing state") or left_side.startswith("billing province"):
            return "Billing state", right_side

        # Administrative
        if left_side.startswith("admin city") or left_side.startswith("administrative city"):
            return "Administrative city", right_side
        if left_side.startswith("admin country") or left_side.startswith("administrative country"):
            return "Administrative country", right_side
        if left_side.startswith("admin organization") or left_side.startswith("administrative organization"):
            return "Administrative organization", right_side
        if left_side.startswith("admin postal code") or left_side.startswith("administrative postal code"):
            return "Administrative postal code", right_side
        if left_side.startswith("admin state") or left_side.startswith("administrative state") or left_side.startswith("admin state/province"):
            return "Administrative state", right_side

        # Technical
        if left_side.startswith("tech city") or left_side.startswith("technical city"):
            return "Technical city", right_side
        if left_side.startswith("tech country") or left_side.startswith("technical country"):
            return "Technical country", right_side
        if left_side.startswith("tech organization") or left_side.startswith("technical organization"):
            return "Technical organization", right_side
        if left_side.startswith("tech postal code") or left_side.startswith("technical postal code"):
            return "Technical postal code", right_side
        if left_side.startswith("tech state") or left_side.startswith("technical state") or left_side.startswith("tech state/province"):
            return "Technical state", right_side

        # Registrant
        if left_side.startswith("registrant city"):
            return "Registrant city", right_side
        if left_side.startswith("registrant country"):
            return "Registrant country", right_side
        if left_side.startswith("registrant organization"):
            return "Registrant organization", right_side
        if left_side.startswith("registrant postal code"):
            return "Registrant postal code", right_side
        if left_side.startswith("registrant state") or left_side.startswith("registrant state/province"):
            return "Registrant state", right_side
        if left_side.startswith("registrant street"):
            return "Registrant street", right_side

        if left_side.startswith("registrant name"):
            return "Registrant name", right_side
        if left_side.startswith("registrant email"):
            return "Registrant email", right_side


        # If unrecognized:
        return None, None

    # ------------------------------------------------------------------------
    # 3) Parsing
    # ------------------------------------------------------------------------
    for raw_line in raw_whois_str.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        key, val = line_to_keyval(line)
        if key is None:
            continue

        # If it's "Domain Status (multi)"
        if key == "Domain Status (multi)":
            # Collect into domain_status_list
            vnorm = normalize_value(val)
            if vnorm:
                domain_status_list.append(vnorm)
            continue

        if key == "Name server (multi)":
            vnorm = normalize_value(val)
            if vnorm:
                current_count = sum(1 for k in candidate_values if k.startswith("Name server "))
                next_field = f"Name server {current_count+1}"
                store_once(next_field, vnorm)
            continue

        # Otherwise store it once
        store_once(key, val)

    # ------------------------------------------------------------------------
    # 4) Merge domain_status_list into a single string
    # ------------------------------------------------------------------------
    if domain_status_list:
        # Join them with commas or semicolons
        merged_status = ", ".join(domain_status_list)
        # Store as "Domain Status"
        candidate_values["Domain Status"] = merged_status

    # Move everything from candidate_values into final 'parsed' dict
    # ignoring empties
    for k, v in candidate_values.items():
        if v:
            parsed[k] = v

    return parsed