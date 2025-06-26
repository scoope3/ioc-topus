"""
ioc_topus.api.validin
~~~~~~~~~~~~~~~~~~~~~
Very small helper around Validin’s “pivots” endpoints.
"""

from __future__ import annotations

import requests
import json              
from queue import Queue
from ioc_topus import config 


def query_validin_domain(domain_str, results_queue):
    """
    If the user selected "Use Validin" for a domain IOC, this function is called.
    It reaches out to:
      https://app.validin.com/api/axon/domain/pivots/<domain>
    and parses the JSON pivot data.
    
    The final structured result is stored in data["validin_dns"] = {...}.
    The results_queue is then updated with a tuple in this form:
         (domain_str, "domain", {"validin_dns": structured_dict}, ["Validin API"], errorOrNone)
    """

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/domain/pivots/{domain_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }

    try:
        # Use the wrapper function instead of requests.get directly.
        resp = validin_request(endpoint, headers)

        resp.raise_for_status()
        data = resp.json()
        # Expected shape: {"records": {"CERT_DOMAIN-IP": [...], "CERT_DOMAIN-HOST": [...], etc.}}
        records = data.get("records", {})
        if not records:
            # possibly no pivot data, so return an empty structure.
            results_queue.put((domain_str, "domain", {"validin_dns": {}}, ["Validin API"], None))
            return


        # Define headers that should remain as lists for pivoting
        LIST_HEADERS = {
            "HOST-CERT_FINGERPRINT","HOST-CERT_FINGERPRINT_SHA256",
            "HOST-HEADER_HASH","HOST-BANNER_0_HASH","HOST-JARM",
            "HOST-BODY_SHA1","HOST-PATH", "HOST-LOCATION", "HOST-LOCATION_DOMAIN", "HOST-CLASS_0_HASH","HOST-CLASS_1_HASH",
            "HOST-LINKS_LINKS"
            
        }

        # Dictionary for headers whose values will be joined into a single string
        validin_cols = {}
        # Dictionary for headers whose values will be kept as lists
        validin_lists = {}

        # Map the pivot record key from Validin
        pivot_to_col = {
             "CERT_DOMAIN-IP": "CERT_DOMAIN-IP",
             "CERT_DOMAIN-HOST": "CERT_DOMAIN-HOST",
             "HOST-LOCATION": "HOST-LOCATION",
             "HOST-LOCATION_DOMAIN": "HOST-LOCATION_DOMAIN",
             "HOST-HEADER_HASH": "HOST-HEADER_HASH",
             "HOST-BANNER": "HOST-BANNER",
             "HOST-BANNER_0_HASH": "HOST-BANNER_0_HASH",
             "HOST-SERVER": "HOST-SERVER",
             "HOST-CERT_FINGERPRINT": "HOST-CERT_FINGERPRINT",
             "HOST-CERT_FINGERPRINT_SHA256": "HOST-CERT_FINGERPRINT_SHA256",
             "HOST-JARM": "HOST-JARM",
             "HOST-CERT_DOMAIN": "HOST-CERT_DOMAIN",
             "HOST-CERT_O": "HOST-CERT_O",
             "HOST-CERT_CN": "HOST-CERT_CN",
             "HOST-CERT_ISSUER": "HOST-CERT_ISSUER",
             "LOCATION_DOMAIN-IP": "LOCATION_DOMAIN-IP",
             "LOCATION_DOMAIN-HOST": "LOCATION_DOMAIN-HOST",
             "JS_LINKS-IP": "JS_LINKS-IP",
             "JS_LINKS-HOST": "JS_LINKS-HOST",
             "HOST-BODY_SHA1": "HOST-BODY_SHA1",
             "HOST-TITLE": "HOST-TITLE",
             "HOST-IFRAMES_LINKS": "HOST-IFRAMES_LINKS",
             "HOST-ANCHORS_LINKS": "HOST-ANCHORS_LINKS",
             "HOST-PATH": "HOST-PATH",
             "HOST-META": "HOST-META",
             "HOST-CERT_ST": "HOST-CERT_ST",
             "HOST-CERT_L": "HOST-CERT_L",
             "HOST-CLASS_0_HASH": "HOST-CLASS_0_HASH",
             "HOST-CLASS_1_HASH": "HOST-CLASS_1_HASH",
             "ANCHORS_LINKS-IP": "ANCHORS_LINKS-IP",
             "ANCHORS_LINKS-HOST": "ANCHORS_LINKS-HOST",
             "HOST-FAVICON_HASH": "HOST-FAVICON_HASH"
        }

        # Iterate through each record type returned by Validin
        for record_type, values_list in records.items():
            col_name = pivot_to_col.get(record_type)
            if not col_name:
                continue # Skip unmapped record types

            current_values = []
            # Extract non-empty, cleaned values for this header
            for item in values_list:
                val_str = item.get("value", "")
                if val_str and str(val_str).strip(): # Check if value is not empty or just whitespace
                    cleaned_val = str(val_str).lstrip(', ') # Strip leading comma/space
                    current_values.append(cleaned_val)

            if not current_values:
                continue # Skip this header entirely if no valid values remain

            if col_name in LIST_HEADERS:
                # Keep as a list (ensure uniqueness and sort for consistency)
                validin_lists[col_name] = sorted(list(set(current_values)))
            else:
                # Join into a single string for the main treeview groups
                # Ensure uniqueness before joining
                unique_values = sorted(list(set(current_values)))
                validin_cols[col_name] = ", ".join(unique_values)

        # Construct the final data dictionary with both grouped and list data
        # Construct the final data dictionary, NESTING under "validin_dns"
        final_data = {
            "validin_dns": { # <--- NEST the results here
                "validin_dns_grouped": validin_cols,  # For the grouped treeviews
                "validin_dns_lists": validin_lists    # For the separate list treeviews
            }
        }

        results_queue.put((domain_str, "domain", final_data, ["Validin API"], None))



    except Exception as e:
        results_queue.put((domain_str, "domain", None, ["Validin API"], str(e)))

def query_validin_domain_dns_history(domain_str, results_queue):
    """
    Queries Validin API for historical DNS records (A, AAAA, NS) for a domain.
    """
    if not config.VALIDIN_API_KEY:
        results_queue.put((domain_str, "domain", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/domain/dns/history/{domain_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }
    
    params = {
        "wildcard": "false",
        "limit": 250
    }

    try:
        print(f"\n=== VALIDIN DNS HISTORY DEBUG ===")
        print(f"Endpoint: {endpoint}")
        print(f"Domain searched: {domain_str}")
        
        resp = validin_request(endpoint, headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"Full DNS History Response:")
        print(json.dumps(data, indent=2))
        print(f"=== END DNS HISTORY DEBUG ===\n")
        
        records = data.get("records", {})
        
        if not records:
            results_queue.put((domain_str, "domain", {"validin_dns_history": {}}, ["Validin API"], None))
            return

        # Process DNS history records
        dns_history_data = []
        for record_type, values_list in records.items():
            for item in values_list:
                if isinstance(item, dict):
                    dns_record = {
                        "record_type": record_type,
                        "value": item.get("value", ""),
                        "first_seen": item.get("first_seen", 0),
                        "last_seen": item.get("last_seen", 0)
                    }
                    dns_history_data.append(dns_record)
        
        final_data = {
            "validin_dns_history": {
                "records": dns_history_data,
                "domain": domain_str,
                "total_records": len(dns_history_data)
            }
        }

        results_queue.put((domain_str, "domain", final_data, ["Validin API"], None))

    except Exception as e:
        results_queue.put((domain_str, "domain", None, ["Validin API"], str(e)))


def query_validin_domain_osint_context(domain_str, results_queue):
    """
    Queries Validin API for OSINT context relevant to domain reputation.
    """
    if not config.VALIDIN_API_KEY:
        results_queue.put((domain_str, "domain", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/domain/osint/context/{domain_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }
    
    params = {
        "wildcard": "false",
        "limit": 250
    }

    try:
        print(f"\n=== VALIDIN OSINT CONTEXT DEBUG ===")
        print(f"Endpoint: {endpoint}")
        print(f"Domain searched: {domain_str}")
        
        resp = validin_request(endpoint, headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"Full OSINT Context Response:")
        print(json.dumps(data, indent=2))
        print(f"=== END OSINT CONTEXT DEBUG ===\n")
        
        records = data.get("records", {})
        observations = records.get("context", [])
        
        final_data = {
            "validin_osint_context": {
                "observations": observations,
                "domain": domain_str,
                "total_observations": len(observations)
            }
        }

        results_queue.put((domain_str, "domain", final_data, ["Validin API"], None))

    except Exception as e:
        results_queue.put((domain_str, "domain", None, ["Validin API"], str(e)))


def query_validin_domain_osint_history(domain_str, results_queue):
    """
    Queries Validin API for all OSINT observations for a domain.
    """
    if not config.VALIDIN_API_KEY:
        results_queue.put((domain_str, "domain", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/domain/osint/history/{domain_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }
    
    params = {
        "wildcard": "false",
        "limit": 250
    }

    try:
        print(f"\n=== VALIDIN OSINT HISTORY DEBUG ===")
        print(f"Endpoint: {endpoint}")
        print(f"Domain searched: {domain_str}")
        
        resp = validin_request(endpoint, headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"Full OSINT History Response:")
        print(json.dumps(data, indent=2))
        print(f"=== END OSINT HISTORY DEBUG ===\n")
        
        records = data.get("records", {})
        observations = records.get("osint", [])
        
        final_data = {
            "validin_osint_history": {
                "observations": observations,
                "domain": domain_str,
                "total_observations": len(observations)
            }
        }

        results_queue.put((domain_str, "domain", final_data, ["Validin API"], None))

    except Exception as e:
        results_queue.put((domain_str, "domain", None, ["Validin API"], str(e)))


def query_validin_domain_dns_extra(domain_str, results_queue):
    """
    Queries Validin API for extra DNS records (MX, TXT, SOA, etc.) for a domain.
    """
    if not config.VALIDIN_API_KEY:
        results_queue.put((domain_str, "domain", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/domain/dns/extra/{domain_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }
    
    params = {
        "wildcard": "false",
        "limit": 250
    }

    try:
        print(f"\n=== VALIDIN DNS EXTRA DEBUG ===")
        print(f"Endpoint: {endpoint}")
        print(f"Domain searched: {domain_str}")
        
        resp = validin_request(endpoint, headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"Full DNS Extra Response:")
        print(json.dumps(data, indent=2))
        print(f"=== END DNS EXTRA DEBUG ===\n")
        
        records = data.get("records", {})
        
        if not records:
            results_queue.put((domain_str, "domain", {"validin_dns_extra": {}}, ["Validin API"], None))
            return

        # Process extra DNS records
        dns_extra_data = []
        for record_type, values_list in records.items():
            for item in values_list:
                if isinstance(item, dict):
                    dns_record = {
                        "record_type": record_type,
                        "value": item.get("value", ""),
                        "first_seen": item.get("first_seen", 0),
                        "last_seen": item.get("last_seen", 0)
                    }
                    dns_extra_data.append(dns_record)
        
        final_data = {
            "validin_dns_extra": {
                "records": dns_extra_data,
                "domain": domain_str,
                "total_records": len(dns_extra_data)
            }
        }

        results_queue.put((domain_str, "domain", final_data, ["Validin API"], None))

    except Exception as e:
        results_queue.put((domain_str, "domain", None, ["Validin API"], str(e)))


def query_validin_domain_crawl_history(domain, results_q):
    """
    Query Validin for the crawl history of a domain.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((domain, "domain", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return

    endpoint = f"https://app.validin.com/api/axon/domain/crawl/history/{domain}"
    print(f"=== VALIDIN DOMAIN CRAWL HISTORY DEBUG ===\nEndpoint: {endpoint}")

    headers = {
        "content-type": "application/json", 
        "Authorization": f"Bearer {api_key}"
    }
    
    params = {
        "limit": 250,
        "wildcard": False,
        "time_format": "iso"
    }

    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        print(f"Domain searched: {domain}\nFull Domain Crawl History Response:\n{json.dumps(data, indent=2)}")
        print("=== END DOMAIN CRAWL HISTORY DEBUG ===")
        
        # Extract crawl data from the correct location: records.crawlr
        crawl_records = data.get("records", {}).get("crawlr", [])
        
        # Transform the complex nested data into a rich format for pivoting
        enhanced_observations = []
        for record in crawl_records:
            value_data = record.get("value", {})
            if isinstance(value_data, dict):
                # Extract comprehensive fields from the nested JSON
                obs = {
                    "date": record.get("first_seen", ""),
                    "scheme": value_data.get("scheme", ""),
                    "port": value_data.get("port", ""),
                    "ip": value_data.get("ip", ""),
                    "title": value_data.get("title", ""),
                    "status": value_data.get("start_line", "").replace("HTTP/1.1 ", "") if value_data.get("start_line") else "",
                    "server": "",  # Will extract from banner
                    "content_type": "",  # Will extract from banner
                    "location_redirect": value_data.get("location", ""),
                    "length": value_data.get("length", ""),
                    "body_hash": value_data.get("body_hash", ""),
                    "header_hash": value_data.get("header_hash", ""),
                    "banner_hash": value_data.get("banner_0_hash", ""),
                    "cert_fingerprint": value_data.get("cert_fingerprint_sha256", ""),
                    "cert_domains": "",  # Will extract from cert_details
                    "jarm": "",  # Will extract from cert_details
                    "external_links": "",  # Will extract from ext_links
                    "class_0_hash": value_data.get("class_0_hash", ""),
                    "class_1_hash": value_data.get("class_1_hash", ""),
                }
                
                # Extract server info from banner
                banner = value_data.get("banner", "")
                if "Server:" in banner:
                    server_line = [line for line in banner.split("\r\n") if line.startswith("Server:")][0]
                    obs["server"] = server_line.replace("Server: ", "").strip()
                
                # Extract content type from banner
                if "Content-Type:" in banner:
                    content_type_line = [line for line in banner.split("\r\n") if line.startswith("Content-Type:")][0]
                    obs["content_type"] = content_type_line.replace("Content-Type: ", "").strip()
                
                # Extract certificate domains and JARM
                cert_details = value_data.get("cert_details", {})
                if cert_details:
                    domains = cert_details.get("domains", [])
                    obs["cert_domains"] = ", ".join(domains) if domains else ""
                    obs["jarm"] = cert_details.get("jarm", "")
                
                # Extract external links
                ext_links = value_data.get("ext_links", {})
                if ext_links:
                    anchors = ext_links.get("anchors", [])
                    obs["external_links"] = ", ".join(anchors) if anchors else ""
                    
            else:
                # Fallback for unexpected data structure
                obs = {
                    "date": record.get("first_seen", ""),
                    "scheme": "", "port": "", "ip": "", "title": "", "status": "",
                    "server": "", "content_type": "", "location_redirect": "",
                    "length": "", "body_hash": "", "header_hash": "", "banner_hash": "",
                    "cert_fingerprint": "", "cert_domains": "", "jarm": "", 
                    "external_links": "", "class_0_hash": "", "class_1_hash": ""
                }
            enhanced_observations.append(obs)
        
        results_q.put((domain, "domain", {"validin_domain_crawl_history": {
            "domain": domain,
            "total_observations": data.get("records_returned", 0),
            "observations": enhanced_observations
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin Domain Crawl History request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((domain, "domain", None, [], error_msg))
    
def query_validin_ip(ip_address, results_queue):
    """
    Queries the Validin API for pivots related to an IP address.
    Parses the results into the same structure as domain queries
    ({"validin_dns": ...}) for consistent display.
    """

    if not config.VALIDIN_API_KEY:
        results_queue.put((ip_address, "ip_address", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/ip/pivots/{ip_address}" # Changed endpoint
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }

    try:
        resp = validin_request(endpoint, headers)
        resp.raise_for_status()
        data = resp.json()
        records = data.get("records", {})

        if not records:
            # No pivot data found
            results_queue.put((ip_address, "ip_address", {"validin_dns": {}}, ["Validin API"], None))
            return


        # Define headers that should remain as lists for pivoting
        LIST_HEADERS = {
            "HOST-CERT_FINGERPRINT","HOST-CERT_FINGERPRINT_SHA256",
            "HOST-HEADER_HASH","HOST-BANNER_0_HASH","HOST-JARM",
            "HOST-BODY_SHA1","HOST-PATH", "HOST-LOCATION", "HOST-LOCATION_DOMAIN", "HOST-CLASS_0_HASH","HOST-CLASS_1_HASH",
            "HOST-LINKS_LINKS"
        }

        # Dictionary for headers whose values will be joined into a single string
        validin_cols = {}
        # Dictionary for headers whose values will be kept as lists
        validin_lists = {}

        # Map the pivot record key (ensure all IP fields are mapped)
        pivot_to_col = {
             "CERT_DOMAIN-IP": "CERT_DOMAIN-IP", "CERT_DOMAIN-HOST": "CERT_DOMAIN-HOST",
             "HOST-LOCATION": "HOST-LOCATION", "HOST-LOCATION_DOMAIN": "HOST-LOCATION_DOMAIN",
             "HOST-HEADER_HASH": "HOST-HEADER_HASH", "HOST-BANNER": "HOST-BANNER",
             "HOST-BANNER_0_HASH": "HOST-BANNER_0_HASH", "HOST-SERVER": "HOST-SERVER",
             "HOST-CERT_FINGERPRINT": "HOST-CERT_FINGERPRINT", "HOST-CERT_FINGERPRINT_SHA256": "HOST-CERT_FINGERPRINT_SHA256",
             "HOST-JARM": "HOST-JARM", "HOST-CERT_DOMAIN": "HOST-CERT_DOMAIN",
             "HOST-CERT_O": "HOST-CERT_O", "HOST-CERT_CN": "HOST-CERT_CN",
             "HOST-CERT_ISSUER": "HOST-CERT_ISSUER", "LOCATION_DOMAIN-IP": "LOCATION_DOMAIN-IP",
             "LOCATION_DOMAIN-HOST": "LOCATION_DOMAIN-HOST", "JS_LINKS-IP": "JS_LINKS-IP",
             "JS_LINKS-HOST": "JS_LINKS-HOST", "HOST-BODY_SHA1": "HOST-BODY_SHA1",
             "HOST-TITLE": "HOST-TITLE", "HOST-IFRAMES_LINKS": "HOST-IFRAMES_LINKS",
             "HOST-ANCHORS_LINKS": "HOST-ANCHORS_LINKS", "HOST-PATH": "HOST-PATH",
             "HOST-META": "HOST-META", "HOST-CERT_ST": "HOST-CERT_ST",
             "HOST-CERT_L": "HOST-CERT_L", "HOST-CLASS_0_HASH": "HOST-CLASS_0_HASH",
             "HOST-CLASS_1_HASH": "HOST-CLASS_1_HASH", "ANCHORS_LINKS-IP": "ANCHORS_LINKS-IP",
             "ANCHORS_LINKS-HOST": "ANCHORS_LINKS-HOST", "HOST-FAVICON_HASH": "HOST-FAVICON_HASH",
             "HOST-LINKS_LINKS": "HOST-LINKS_LINKS",
             "HOST-LOCATION_IP4": "HOST-LOCATION_IP4",
         } 
        
        for record_type in records.keys():
             if record_type not in pivot_to_col:
                 pivot_to_col[record_type] = record_type # Add direct mapping

        # Iterate through each record type returned by Validin
        for record_type, values_list in records.items():
            col_name = pivot_to_col.get(record_type)
            if not col_name:
                 print(f"[Warning] Unhandled Validin IP record type: {record_type}")
                 continue # Skip unmapped record types

            current_values = []
            # Extract non-empty, cleaned values for this header
            for item in values_list:
                val_str = item.get("value", "")
                if val_str and str(val_str).strip(): # Check if value is not empty or just whitespace
                    cleaned_val = str(val_str).lstrip(', ') # Strip leading comma/space
                    current_values.append(cleaned_val)

            if not current_values:
                continue # Skip this header entirely if no valid values remain

            if col_name in LIST_HEADERS:
                # Keep as a list (ensure uniqueness and sort for consistency)
                validin_lists[col_name] = sorted(list(set(current_values)))
            else:
                # Join into a single string for the main treeview groups
                # Ensure uniqueness before joining
                unique_values = sorted(list(set(current_values)))
                validin_cols[col_name] = ", ".join(unique_values)

        # Construct the final data dictionary, nesting under "validin_dns" structure for consistency
        final_data = {
            "validin_dns": { 
                 "validin_dns_grouped": validin_cols,  # For the grouped treeviews
                 "validin_dns_lists": validin_lists    # For the separate list treeviews
             }
        }


        results_queue.put((ip_address, "ip_address", final_data, ["Validin API"], None))


    except Exception as e:
        results_queue.put((ip_address, "ip_address", None, ["Validin API"], str(e)))


def query_validin_ip_dns_history(ip, results_q):
    """
    Query Validin for the passive DNS history of an IP address.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((ip, "ip_address", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return

    endpoint = f"https://app.validin.com/api/axon/ip/dns/history/{ip}"
    print(f"=== VALIDIN IP DNS HISTORY DEBUG ===\nEndpoint: {endpoint}")

    headers = {
        "content-type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    params = {"time_format": "iso"}

    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        print(f"IP searched: {ip}\nFull IP DNS History Response:\n{json.dumps(data, indent=2)}")
        print("=== END IP DNS HISTORY DEBUG ===")

        observations = []
        records = data.get("records", {})
        for record_type, record_list in records.items():
            for record in record_list:
                observations.append({
                    "hostname": record.get("value"),
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen"),
                    "record_type": record_type
                })

        results_q.put((ip, "ip_address", {"validin_ip_dns_history": {
            "ip": ip,
            "total_observations": data.get("records_returned", 0),
            "observations": observations
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin IP DNS History request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((ip, "ip_address", None, [], error_msg))


def query_validin_ip_dns_extra(ip, results_q):
    """
    Query Validin for extra DNS records for an IP.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((ip, "ip_address", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return

    endpoint = f"https://app.validin.com/api/axon/ip/dns/extra/{ip}"
    print(f"=== VALIDIN IP DNS EXTRA DEBUG ===\nEndpoint: {endpoint}")

    headers = {
        "content-type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    params = {"time_format": "iso"}

    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        print(f"IP searched: {ip}\nFull IP DNS Extra Response:\n{json.dumps(data, indent=2)}")
        print("=== END IP DNS EXTRA DEBUG ===")

        observations = []
        records = data.get("records", {})
        for record_type, record_list in records.items():
            for record in record_list:
                observations.append({
                    "type": record_type,
                    "value": record.get("value"),
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen")
                })

        results_q.put((ip, "ip_address", {"validin_ip_dns_extra": {
            "ip": ip,
            "total_observations": data.get("records_returned", 0),
            "observations": observations
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin IP DNS Extra request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((ip, "ip_address", None, [], error_msg))


def query_validin_ip_osint_history(ip, results_q):
    """
    Query Validin for the OSINT history of an IP address.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((ip, "ip_address", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return

    endpoint = f"https://app.validin.com/api/axon/ip/osint/history/{ip}"
    print(f"=== VALIDIN IP OSINT HISTORY DEBUG ===\nEndpoint: {endpoint}")

    headers = {
        "content-type": "application/json", 
        "Authorization": f"Bearer {api_key}"
    }
    
    params = {"time_format": "iso"}

    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        print(f"IP searched: {ip}\nFull IP OSINT History Response:\n{json.dumps(data, indent=2)}")
        print("=== END IP OSINT HISTORY DEBUG ===")
        
        results_q.put((ip, "ip_address", {"validin_ip_osint_history": {
            "ip": ip,
            "total_observations": data.get("records_returned", 0),
            "observations": data.get("records", {}).get("osint", [])
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin IP OSINT History request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((ip, "ip_address", None, [], error_msg))


def query_validin_ip_osint_context(ip, results_q):
    """
    Query Validin for the OSINT context of an IP address.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((ip, "ip_address", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return
    
    endpoint = f"https://app.validin.com/api/axon/ip/osint/context/{ip}"
    print(f"=== VALIDIN IP OSINT CONTEXT DEBUG ===\nEndpoint: {endpoint}")
    
    headers = {
        "content-type": "application/json", 
        "Authorization": f"Bearer {api_key}"
    }
    
    params = {"time_format": "iso"}
    
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        print(f"IP searched: {ip}\nFull IP OSINT Context Response:\n{json.dumps(data, indent=2)}")
        print("=== END IP OSINT CONTEXT DEBUG ===")
        
        results_q.put((ip, "ip_address", {"validin_ip_osint_context": {
            "ip": ip,
            "total_observations": data.get("records_returned", 0),
            "observations": data.get("records", {}).get("context", [])
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin IP OSINT Context request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((ip, "ip_address", None, [], error_msg))


def query_validin_ip_crawl_history(ip, results_q):
    """
    Query Validin for the crawl history of an IP address.
    """
    api_key = config.VALIDIN_API_KEY
    if not api_key:
        results_q.put((ip, "ip_address", {"error": "Validin API key not configured."}, ["Validin API"], "Validin API key not set."))
        return

    endpoint = f"https://app.validin.com/api/axon/ip/crawl/history/{ip}"
    print(f"=== VALIDIN IP CRAWL HISTORY DEBUG ===\nEndpoint: {endpoint}")

    headers = {
        "content-type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        data = response.json()
        print(f"IP searched: {ip}\nFull IP Crawl History Response:\n{json.dumps(data, indent=2)}")
        print("=== END IP CRAWL HISTORY DEBUG ===")

        observations = []
        # The crawl history records are under the 'crawlr' key
        records = data.get("records", {}).get("crawlr", [])
        for record in records:
            # The interesting details are in the nested 'value' dictionary.
            observation = record.get("value", {})

            # Add the 'first_seen' and 'last_seen' timestamps from the parent object.
            observation['first_seen'] = record.get('first_seen')
            observation['last_seen'] = record.get('last_seen')
            
            observations.append(observation)

        # Send the processed data to the results queue
        results_q.put((ip, "ip_address", {"validin_ip_crawl_history": {
            "ip": ip,
            "total_observations": data.get("records_returned", 0),
            "observations": observations
        }}, ["Validin API"], None))

    except Exception as e:
        error_msg = f"Validin IP Crawl History request failed: {e}"
        print(f"[ERROR] {error_msg}")
        results_q.put((ip, "ip_address", None, [], error_msg))
    
def query_validin_hash(hash_str, results_queue):
    """
    Queries the Validin API for pivots related to a hash/fingerprint.
    This uses the general hash pivot endpoint that searches across all categories.
    
    Hash categories supported by Validin:
    - BANNER_0_HASH
    - BODY_SHA1
    - CERT_FINGERPRINT
    - CERT_FINGERPRINT_SHA256
    - CLASS_0_HASH
    - CLASS_1_HASH
    - FAVICON_HASH
    - HEADER_HASH
    - JARM
    """
    
    if not config.VALIDIN_API_KEY:
        results_queue.put((hash_str, "fingerprint_hash", None, ["Validin API"], "No Validin API key set"))
        return

    base_url = "https://app.validin.com/api/axon"
    endpoint = f"{base_url}/hash/pivots/{hash_str}"
    headers = {
        "Authorization": f"Bearer {config.VALIDIN_API_KEY}"
    }
    
    # Add query parameters for better results
    params = {
        "limit": 250,
        "wildcard": "false"
    }

    try:
        print(f"\n=== VALIDIN HASH API DEBUG ===")
        print(f"Endpoint: {endpoint}")
        print(f"Hash searched: {hash_str}")
        
        resp = validin_request(endpoint, headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        # Print the full response for debugging
        print(f"Full API Response:")
        import json
        print(json.dumps(data, indent=2))
        print(f"=== END VALIDIN DEBUG ===\n")
        
        records = data.get("records", {})
        
        if not records:
            # No pivot data found
            results_queue.put((hash_str, "fingerprint_hash", {"validin_hash_pivots": {}}, ["Validin API"], None))
            return

        # Process the records into a structured format
        all_pivots = []
        
        for record_type, values_list in records.items():
            # Extract the category (IP or HOST) from record type
            if "-IP" in record_type:
                indicator_type = "IP"
            elif "-HOST" in record_type:
                indicator_type = "Domain"
            else:
                indicator_type = "Unknown"
            
            for item in values_list:
                if isinstance(item, dict):
                    pivot_data = {
                        "indicator": item.get("value", ""),
                        "indicator_type": indicator_type,
                        "first_seen": item.get("first_seen", 0),
                        "last_seen": item.get("last_seen", 0),
                        "record_type": record_type
                    }
                    all_pivots.append(pivot_data)
        
        # Sort by indicator type then by value
        all_pivots.sort(key=lambda x: (x["indicator_type"], x["indicator"]))
        
        # Construct the final data dictionary
        final_data = {
            "validin_hash_pivots": {
                "pivot_data": all_pivots,
                "searched_hash": hash_str,
                "total_results": len(all_pivots)
            }
        }

        results_queue.put((hash_str, "fingerprint_hash", final_data, ["Validin API"], None))

    except Exception as e:
        results_queue.put((hash_str, "fingerprint_hash", None, ["Validin API"], str(e)))


# Update the validin_request function to accept params
def validin_request(url, headers, params=None):
    """
    Wraps a GET request to the Validin endpoint.
    Quota checked via API.
    """
    response = requests.get(url, headers=headers, params=params, timeout=15)
    return response