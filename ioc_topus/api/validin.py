"""
ioc_topus.api.validin
~~~~~~~~~~~~~~~~~~~~~
Very small helper around Validin’s “pivots” endpoints.
"""

from __future__ import annotations

import requests               
from typing import Dict

from ioc_topus import config  # single-source-of-truth for API keys


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
            "validin_dns": { # Keep the original top-level key expected by merging logic
                 "validin_dns_grouped": validin_cols,  # For the grouped treeviews
                 "validin_dns_lists": validin_lists    # For the separate list treeviews
             }
        }


        results_queue.put((ip_address, "ip_address", final_data, ["Validin API"], None))


    except Exception as e:
        results_queue.put((ip_address, "ip_address", None, ["Validin API"], str(e)))

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