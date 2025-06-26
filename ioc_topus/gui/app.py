# ─── Std-lib ────────────────────────────────────────────────
import json
import os
import csv
import queue
import re
import time
import threading
import webbrowser
from datetime import datetime, timezone
from io import BytesIO

# ─── Third-party ────────────────────────────────────────────
import requests
from PIL import Image, ImageTk       # pip install pillow

# ─── Tkinter (built-in) ─────────────────────────────────────
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─── Project modules (ioc_topus package) ────────────────────
from ioc_topus.core.ioc            import validate_ioc
from ioc_topus.core.processor      import (
    process_iocs,
    process_iocs_with_selective_apis
)
from ioc_topus.core.merge          import merge_api_results       
from ioc_topus.api.virustotal      import parse_virustotal_whois
from ioc_topus.utils.crypto        import decrypt_string, encrypt_string
from ioc_topus.utils.helpers       import pivot_bodyhash_search
from ioc_topus.gui.widgets         import SmoothScrolledFrame

from ioc_topus import config # gives us config.VT_API_KEY, …
from ioc_topus.config import persist_api_keys
from ioc_topus.core import processor as _proc

def build_gui():
    """
    Builds the main UI window for IOC-Topus. This function sets up the entire
    Tkinter-based interface, including the main tree for IOCs, various notebook
    tabs for analysis details, and all supporting functions for fetching data,
    pivoting, and interacting with external APIs (VirusTotal, urlscan, etc.).
    """
    # ------------------------------------------------------------------------
    # 1) GLOBAL VARIABLES & CONSTANTS
    # ------------------------------------------------------------------------
    global BACKGROUND_COLOR, TEXT_COLOR, FONT_LABEL, FONT_TREE, FONT_BUTTON, FONT_HEADER, FONT_STATUS
    global HEADER_COLOR, BUTTON_COLOR, ALTERNATE_ROW_COLOR
    global response_cache, API_REQUESTS_MADE, API_REQUESTS_PER_DAY
    global tree, status_bar, progress_bar
    global ioc_fields_scrolled, ioc_fields_inner
    global relationships_scrolled, relationships_inner
    global dynamic_analysis_scrolled, dynamic_analysis_inner
    global static_analysis_scrolled, static_analysis_inner
    global certificates_scrolled, certificates_inner
    global dns_scrolled, dns_inner
    global web_analysis_scrolled, web_analysis_inner

    BACKGROUND_COLOR = "#F0F0F0"
    TEXT_COLOR = "#000000"
    HEADER_COLOR = "#6A5ACD"
    BUTTON_COLOR = "#9370DB"
    ALTERNATE_ROW_COLOR = "#E8E8E8"

    FONT_HEADER = ("Segoe UI", 16, "bold")
    FONT_LABEL = ("Segoe UI", 12)
    FONT_BUTTON = ("Segoe UI", 10)
    FONT_TREE = ("Segoe UI", 10)
    FONT_STATUS = ("Segoe UI", 9)

    if "response_cache" not in globals():
        response_cache = {}
    if "API_REQUESTS_MADE" not in globals():
        API_REQUESTS_MADE = 0
    if "API_REQUESTS_PER_DAY" not in globals():
        API_REQUESTS_PER_DAY = 500

    # ------------------------------------------------------------------------
    # 2) INITIALIZE THE MAIN TK ROOT
    # ------------------------------------------------------------------------

    root = tk.Tk()
    blank_img = tk.PhotoImage(width=1, height=1)  # 1×1 transparent
    root.iconphoto(False, blank_img)
    root.title("IOC-Topus")
    root.geometry("1200x800")
    root.configure(bg=BACKGROUND_COLOR)

    # ------------------------------------------------------------------------
    # 3) CREATE CONFIGURATION & STYLES
    # ------------------------------------------------------------------------
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="white", foreground="black", rowheight=22, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    style.configure("TLabelFrame", background=BACKGROUND_COLOR)
    style.configure("Bold.TLabelframe.Label", font=("Segoe UI", 12, "bold"))

    # ------------------------------------------------------------------------
    # 4) DEFINE HELPER / UTILITY FUNCTIONS
    #    
    # ------------------------------------------------------------------------  

    def clean_ioc_for_display(ioc_value):
        """Ensures IOC value is clean for display"""
        if not ioc_value:
            return "Unknown"
        
        ioc_str = str(ioc_value)
        
        # If it contains data structure elements, it's wrong
        if any(x in ioc_str for x in ['{', '[', '"reputation"', '"http_response"']):
            # Try to extract a URL
            import re
            url_match = re.search(r'https?://[^\s\'"{}]+', ioc_str)
            if url_match:
                return url_match.group(0)
            return "Invalid IOC"
        
        return ioc_str


    def show_match_data_popup(title, match_data_list):
        """Creates a popup window to display signature match details."""
        popup = tk.Toplevel()
        popup.title(title)
        popup.geometry("600x400")
        popup.configure(bg="#F0F0F0")

        # Frame for the text box and scrollbar
        text_frame = tk.Frame(popup, bg="#F0F0F0")
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        v_scroll = tk.Scrollbar(text_frame, orient="vertical")
        h_scroll = tk.Scrollbar(text_frame, orient="horizontal")
        text_box = tk.Text(
            text_frame,
            wrap="none",  # Use none for horizontal scrolling
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set,
            font=("Consolas", 10) # Use a fixed-width font for better alignment
        )

        v_scroll.config(command=text_box.yview)
        v_scroll.pack(side="right", fill="y")
        h_scroll.config(command=text_box.xview)
        h_scroll.pack(side="bottom", fill="x")
        text_box.pack(side="left", fill="both", expand=True)

        # Insert the formatted data
        if not match_data_list:
            text_box.insert("1.0", "No match data available.")
        else:
            # Format the list nicely (e.g., one item per line or JSON)
            formatted_text = json.dumps(match_data_list, indent=2)
            # formatted_text = "\n".join(str(item) for item in match_data_list)
            text_box.insert("1.0", formatted_text)

        text_box.config(state="disabled") 

        # Add a close button
        close_btn = tk.Button(popup, text="Close", command=popup.destroy, bg="#6A5ACD", fg="white")
        close_btn.pack(pady=(0, 10))

        popup.transient(root) 
        popup.grab_set()      
        root.wait_window(popup) # Wait until popup is closed

    def show_dynamic_analysis_popup(title, dynamic_data_dict):
            """Creates a popup window to display detailed dynamic analysis data."""
            popup = tk.Toplevel(root) 
            popup.title(title)
            popup.geometry("700x500") 
            popup.configure(bg="#F0F0F0")

            # Main container for scrollable content
            scroll_frame = SmoothScrolledFrame(popup, bg_color="#F0F0F0")
            scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
            inner_frame = scroll_frame.get_inner_frame()

            if not dynamic_data_dict:
                tk.Label(inner_frame, text="No dynamic analysis data available for this file.", bg="#F0F0F0", font=FONT_LABEL).pack(pady=10)
            else:
                # Section for Sigma Analysis Results
                sigma_results = dynamic_data_dict.get("sigma_analysis_results", [])
                if sigma_results:
                    sigma_lf = tk.LabelFrame(inner_frame, text="Sigma Analysis Results", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=5, pady=5)
                    sigma_lf.pack(fill="x", expand=True, pady=(0, 10))
                    
                    # Each sigma result can have complex match_context
                    for i, sigma_item in enumerate(sigma_results):
                        rule_title = sigma_item.get("rule_name", sigma_item.get("rule_title", f"Sigma Rule {i+1}"))
                        item_lf = tk.LabelFrame(sigma_lf, text=f"{rule_title} (Level: {sigma_item.get('rule_level','N/A')}, ID: {sigma_item.get('rule_id','N/A')})", font=("Segoe UI", 10, "bold"), bg="#F0F0F0", padx=5, pady=5)
                        item_lf.pack(fill="x", expand=True, pady=5)
                        
                        match_context_str = sigma_item.get("match_context", "No match context.")
                        try:
                            match_context_data = json.loads(match_context_str)
                            formatted_text = json.dumps(match_context_data, indent=2)
                        except (json.JSONDecodeError, TypeError):
                            # Fallback to string if not a valid JSON string or already a dict/list
                            if isinstance(match_context_str, (dict, list)):
                                formatted_text = json.dumps(match_context_str, indent=2)
                            else:
                                formatted_text = str(match_context_str)

                        create_textbox_with_scroll(item_lf, formatted_text, "#FFFFFF", ("Consolas", 9), 80, 5, include_copy_button=True)
                else:
                    tk.Label(inner_frame, text="No Sigma analysis results.", bg="#F0F0F0", font=FONT_LABEL).pack(pady=5)

                # Section for Crowdsourced IDS Results
                crowdsourced_results = dynamic_data_dict.get("crowdsourced_ids_results", [])
                if crowdsourced_results:
                    csc_lf = tk.LabelFrame(inner_frame, text="Crowdsourced IDS Results", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=5, pady=5)
                    csc_lf.pack(fill="x", expand=True, pady=(10, 0))

                    for i, csc_item in enumerate(crowdsourced_results):
                        rule_msg = csc_item.get("rule_msg", f"Crowdsourced Rule {i+1}")
                        item_lf = tk.LabelFrame(csc_lf, text=f"{rule_msg} (Severity: {csc_item.get('alert_severity','N/A')}, Category: {csc_item.get('rule_category','N/A')})", font=("Segoe UI", 10, "bold"), bg="#F0F0F0", padx=5, pady=5)
                        item_lf.pack(fill="x", expand=True, pady=5)
                        
                        alert_context_list = csc_item.get("alert_context", [])
                        if alert_context_list:
                            formatted_text = json.dumps(alert_context_list, indent=2)
                        else:
                            formatted_text = "No alert context for this rule."
                        create_textbox_with_scroll(item_lf, formatted_text, "#FFFFFF", ("Consolas", 9), 80, 5, include_copy_button=True)
                else:
                    tk.Label(inner_frame, text="No Crowdsourced IDS results.", bg="#F0F0F0", font=FONT_LABEL).pack(pady=5)

            close_btn = tk.Button(popup, text="Close", command=popup.destroy, bg="#6A5ACD", fg="white", font=FONT_BUTTON)
            close_btn.pack(pady=(10,10))

            popup.transient(root)
            popup.grab_set()
            root.wait_window(popup)


    def open_api_usage_popup():
        """
        Displays API usage statistics.
        """
        popup = tk.Toplevel(root)
        popup.title("API Usage Information")
        popup.configure(bg="#F0F0F0")
        popup.geometry("450x420")
        popup.resizable(False, False)

        container = tk.Frame(popup, bg="#F0F0F0", padx=15, pady=15)
        container.pack(fill="both", expand=True)

        lbl_title = tk.Label(
            container,
            text="API Usage Information",
            font=("Segoe UI", 14, "bold"),
            bg="#F0F0F0"
        )
        lbl_title.pack(pady=(0, 15))

        def get_usage_color(used, limit):
            if limit is None or limit == 0: return "black"
            if used is None: return "grey"
            remaining = limit - used
            ratio_remaining = float(remaining) / float(limit)
            if ratio_remaining <= 0.0: return "red"
            elif ratio_remaining <= 0.2: return "darkorange"
            else: return "black"

        # --- urlscan.io Section ---
        st_frame = tk.LabelFrame(
            container, text="urlscan.io", bg="#F0F0F0",
            font=("Segoe UI", 11, "bold"), padx=10, pady=10
        )
        st_frame.pack(fill="x", pady=5)
        if not config.URLSCAN_API_KEY:
            tk.Label(st_frame, text="API Key not set.", bg="#F0F0F0", fg="grey", font=FONT_LABEL).pack(anchor="w", padx=10)
        else:
            st_public_label = tk.Label(st_frame, text="Public scans: Fetching...", bg="#F0F0F0", font=FONT_LABEL); st_public_label.pack(anchor="w", padx=10, pady=1)
            st_private_label = tk.Label(st_frame, text="Private scans: Fetching...", bg="#F0F0F0", font=FONT_LABEL); st_private_label.pack(anchor="w", padx=10, pady=1)
            st_search_label = tk.Label(st_frame, text="Search requests: Fetching...", bg="#F0F0F0", font=FONT_LABEL); st_search_label.pack(anchor="w", padx=10, pady=1)
            st_retrieve_label = tk.Label(st_frame, text="Result retrieval: Fetching...", bg="#F0F0F0", font=FONT_LABEL); st_retrieve_label.pack(anchor="w", padx=10, pady=1)
            def fetch_and_display_st_quota():
                st_url = "https://urlscan.io/user/quotas/"; st_headers = {"Content-Type": "application/json", "API-Key": config.URLSCAN_API_KEY}; err_msg = None; quota_data = {}
                try:
                    resp = requests.get(st_url, headers=st_headers, timeout=10); resp.raise_for_status(); quota_data = resp.json().get("limits", {})
                except Exception as e: err_msg = f"Error: {type(e).__name__}"
                def update_st_labels():
                    if err_msg:
                        st_public_label.config(text=f"Public scans: {err_msg}", fg="red")
                    elif quota_data:
                        pub_u, pub_l = quota_data.get("public", {}).get("day", {}).get("used"), quota_data.get("public", {}).get("day", {}).get("limit")
                        priv_u, priv_l = quota_data.get("private", {}).get("day", {}).get("used"), quota_data.get("private", {}).get("day", {}).get("limit")
                        sr_u, sr_l = quota_data.get("search", {}).get("day", {}).get("used"), quota_data.get("search", {}).get("day", {}).get("limit")
                        re_u, re_l = quota_data.get("retrieve", {}).get("day", {}).get("used"), quota_data.get("retrieve", {}).get("day", {}).get("limit")
                        st_public_label.config(text=f"Public scans: {pub_u}/{pub_l}", fg=get_usage_color(pub_u, pub_l)); st_private_label.config(text=f"Private scans: {priv_u}/{priv_l}", fg=get_usage_color(priv_u, priv_l)); st_search_label.config(text=f"Search requests: {sr_u}/{sr_l}", fg=get_usage_color(sr_u, sr_l)); st_retrieve_label.config(text=f"Result retrieval: {re_u}/{re_l}", fg=get_usage_color(re_u, re_l))
                if popup.winfo_exists(): popup.after(0, update_st_labels)
            threading.Thread(target=fetch_and_display_st_quota, daemon=True).start()

        # --- VirusTotal Section ---
        vt_frame = tk.LabelFrame(
            container, text="VirusTotal", bg="#F0F0F0",
            font=("Segoe UI", 11, "bold"), padx=10, pady=10
        )
        vt_frame.pack(fill="x", pady=5)
        if not config.VT_API_KEY:
            tk.Label(vt_frame, text="API Key not set.", bg="#F0F0F0", fg="grey", font=FONT_LABEL).pack(anchor="w", padx=10, pady=5)
        else:
            vt_info_label = tk.Label(vt_frame, text="Please check your account dashboard for quota.", bg="#F0F0F0", fg="blue", cursor="hand2", font=FONT_LABEL)
            vt_info_label.pack(anchor="w", padx=10, pady=5)
            vt_info_label.bind("<Button-1>", lambda e: webbrowser.open("https://www.virustotal.com/gui/user/pundles/api-plans"))

        # --- Validin Section ---
        val_frame = tk.LabelFrame(
            container, text="Validin", bg="#F0F0F0",
            font=("Segoe UI", 11, "bold"), padx=10, pady=10
        )
        val_frame.pack(fill="x", pady=5)
        if not config.VALIDIN_API_KEY:
            tk.Label(val_frame, text="API Key not set.", bg="#F0F0F0", fg="grey", font=FONT_LABEL).pack(anchor="w", padx=10, pady=5)
        else:
            daily_label = tk.Label(val_frame, text="Daily Remaining: Fetching...", bg="#F0F0F0", font=FONT_LABEL); daily_label.pack(anchor="w", padx=10, pady=1)
            monthly_label = tk.Label(val_frame, text="Monthly Remaining: Fetching...", bg="#F0F0F0", font=FONT_LABEL); monthly_label.pack(anchor="w", padx=10, pady=(1, 5))
            def fetch_and_display_validin_quota():
                usage_url = "https://app.validin.com/api/profile/usage"; headers = {"Authorization": f"Bearer {config.VALIDIN_API_KEY}"}; daily_rem, monthly_rem = "Error", "Error"
                try:
                    response = requests.get(usage_url, headers=headers, timeout=10); response.raise_for_status(); data = response.json(); remaining_data = data.get("remaining", {})
                    daily_rem = remaining_data.get("daily"); monthly_rem = remaining_data.get("monthly")
                    daily_label.config(text=f"Daily Remaining: {daily_rem if daily_rem is not None else 'N/A'}", fg="black")
                    monthly_label.config(text=f"Monthly Remaining: {monthly_rem if monthly_rem is not None else 'N/A'}", fg="black")
                except Exception as e:
                    daily_label.config(text=f"Daily Remaining: Error ({type(e).__name__})", fg="red")
                    monthly_label.config(text=f"Monthly Remaining: Error ({type(e).__name__})", fg="red")
            threading.Thread(target=fetch_and_display_validin_quota, daemon=True).start()



    def robust_poll_virustotal_analysis(analysis_id, headers, max_wait=300):
        """
        Polls https://www.virustotal.com/api/v3/analyses/<analysis_id> until status='completed'
        or max_wait seconds pass. Returns (analysis_json, error_str).
        """
        start_time = time.time()
        poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait:
                return (None, f"VirusTotal analysis not completed after {max_wait} seconds.")

            resp = requests.get(poll_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    return (data, None)
                elif status in ("queued", "in-progress"):
                    time.sleep(5)
                    continue
                else:
                    return (None, f"VT analysis ended with unexpected status: {status}")
            elif resp.status_code in (429, 503):
                # Rate limited or service unavailable, wait and retry
                time.sleep(5)
                continue
            else:
                return (None, f"VT poll error {resp.status_code}: {resp.text}")

    def robust_poll_urlscan(scan_uuid, headers, max_wait=90):
        """
        Polls https://urlscan.io/api/v1/result/<uuid> until the report is ready or max_wait expires.
        Returns (json_data, error_str).
        """
        start_time = time.time()
        poll_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"

        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait:
                return (None, f"urlscan not ready after {max_wait} seconds.")

            resp = requests.get(poll_url, headers=headers)
            if resp.status_code == 200:
                return (resp.json(), None)
            elif resp.status_code in (404, 429, 500, 503):
                time.sleep(5)
                continue
            else:
                return (None, f"urlscan poll error {resp.status_code}: {resp.text}")


    def submit_indicator_logic_robust(ioc_value, mode, submit_to_vt, submit_to_us, visibility, results_q):
        """
        1) Submits the IOC (URL or file) to VirusTotal if checked.
        2) Submits a URL to urlscan if checked.
        3) Polls each service for the final/complete analysis.
        4) Then calls the existing process_iocs([ioc_value]) to do the "final" GET.
        5) Puts final result in 'results_q' as (ioc, ioc_type, parsed_data, sources, error_str).
        """
        # Store the original IOC value before any modifications
        original_ioc_value = str(ioc_value).strip()
        new_sha256 = None  # Track SHA256 for file submissions
        
        vt_err = None
        us_err = None

        # Check if it's only a domain submitted as URL
        actual_mode = mode
        if actual_mode == "url":
            # Check if it's only a domain (no protocol, no path)
            if not re.match(r"^https?://", ioc_value, re.IGNORECASE):
                # It's likely a domain or domain with port, add protocol
                if "/" not in ioc_value or (ioc_value.count("/") == 1 and ioc_value.endswith("/")):
                    # Check if it looks like a domain
                    domain_pattern = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?[A-Za-z]{0,}(:[0-9]+)?/?$"
                    if re.match(domain_pattern, ioc_value):
                        # Remove trailing slash if present
                        ioc_value = ioc_value.rstrip("/")
                        # Add protocol
                        if ":" in ioc_value and not ioc_value.startswith("http"):
                            # Has port
                            ioc_value = f"http://{ioc_value}"
                        else:
                            ioc_value = f"http://{ioc_value}"
                            
        # ----------------------------------
        # 1) VIRUSTOTAL SUBMISSION
        # ----------------------------------
        if submit_to_vt and config.VT_API_KEY:
            headers_vt = {
                "accept": "application/json",
                "x-apikey": config.VT_API_KEY
            }
            try:
                if mode == "url":
                    # Submit URL to VT
                    vt_url = "https://www.virustotal.com/api/v3/urls"
                    post_data = f"url={ioc_value}"
                    headers_vt["content-type"] = "application/x-www-form-urlencoded"
                    resp = requests.post(vt_url, headers=headers_vt, data=post_data)

                    if resp.status_code == 200:
                        analysis_id = resp.json()["data"]["id"]
                        final_json, poll_err = robust_poll_virustotal_analysis(
                            analysis_id, headers_vt, max_wait=300
                        )
                        if poll_err:
                            vt_err = poll_err

                    else:
                        vt_err = f"VT submission error {resp.status_code}: {resp.text}"

                else:
                    # Submit FILE to VT
                    vt_url = "https://www.virustotal.com/api/v3/files"
                    try:
                        with open(ioc_value, "rb") as f:
                            files_dict = {"file": f}
                            resp = requests.post(vt_url, headers=headers_vt, files=files_dict)

                        if resp.status_code == 200:
                            analysis_id = resp.json()["data"]["id"]
                            # Poll until analysis is complete
                            final_json, poll_err = robust_poll_virustotal_analysis(
                                analysis_id, headers_vt, max_wait=300
                            )
                            if poll_err:
                                vt_err = poll_err
                            else:
                                try:
                                    new_sha256 = final_json["meta"]["file_info"]["sha256"]
                                    ioc_value = new_sha256  # reassign the IOC to the actual SHA-256
                                except KeyError:
                                    vt_err = ("Could not extract SHA256 from final JSON "
                                            "after file submission.")
                        else:
                            vt_err = f"VT file submit error {resp.status_code}: {resp.text}"
                    except Exception as ex:
                        vt_err = f"Error reading file '{ioc_value}': {ex}"

            except Exception as e:
                vt_err = str(e)

        # ----------------------------------
        # 2) URLSCAN SUBMISSION
        # ----------------------------------
        if submit_to_us and config.URLSCAN_API_KEY:
            if mode == "url":
                try:
                    urlscan_url = "https://urlscan.io/api/v1/scan/"
                    headers_us = {
                        "API-Key": config.URLSCAN_API_KEY,
                        "Content-Type": "application/json"
                    }
                    # Ensure the URL is properly formatted for URLScan
                    submit_url = ioc_value
                    if not re.match(r"^https?://", submit_url, re.IGNORECASE):
                        submit_url = f"http://{submit_url}"
                        
                    body = {"url": submit_url, "visibility": visibility}
                    resp = requests.post(urlscan_url, headers=headers_us, json=body)

                    if resp.status_code in (200, 201):
                        j = resp.json()
                        uuid = j.get("uuid")
                        final_data, poll_err = robust_poll_urlscan(uuid, headers_us, max_wait=90)
                        if poll_err:
                            us_err = poll_err
                    else:
                        # Parse the error response for better error messages
                        try:
                            error_data = resp.json()
                            if "message" in error_data:
                                us_err = f"urlscan error: {error_data['message']}"
                            else:
                                us_err = f"urlscan submission error {resp.status_code}: {resp.text}"
                        except:
                            us_err = f"urlscan submission error {resp.status_code}: {resp.text}"
                            
                except Exception as ex:
                    us_err = f"Error submitting to urlscan: {ex}"
            else: # mode == "file" - urlscan submission is only for URLs
                pass

        # Continue with the rest of the function...
        def do_final_lookup():
            all_errors = []
            if vt_err:
                all_errors.append(f"VT submission error: {vt_err}")
            if us_err:
                all_errors.append(f"urlscan submission error: {us_err}")
            final_err = " | ".join(all_errors) if all_errors else None

            # Determine which IOC to use for the final lookup
            final_ioc_to_query = ioc_value  # This might be the SHA256 for files
            
            # For file submissions, validate we have a proper SHA256
            if mode == "file" and not re.match(r"^[a-fA-F0-9]{64}$", ioc_value):
                results_q.put((original_ioc_value, "file", {"file_submitted": True}, [], final_err))
                return

            if final_ioc_to_query in response_cache:
                del response_cache[final_ioc_to_query]

            qlocal = queue.Queue()
            process_iocs([final_ioc_to_query], qlocal)
            final_result = qlocal.get()

            if len(final_result) == 5:
                ioc_final, itype_final, parsed_data, sources_final, err_final = final_result
            else:
                ioc_final, itype_final, parsed_data, sources_final = final_result
                err_final = None

            if isinstance(ioc_final, dict) or any(x in str(ioc_final) for x in ['{', '"http_response_data"', '"reputation"']):
                print(f"ERROR: Submission corrupted IOC to: {ioc_final}")
                # For files, use the SHA256 if we have it, otherwise use original
                if mode == "file" and new_sha256:
                    ioc_final = new_sha256
                else:
                    ioc_final = original_ioc_value

            if err_final:
                if final_err:
                    final_err += " | " + err_final
                else:
                    final_err = err_final

            results_q.put((ioc_final, itype_final, parsed_data, sources_final, final_err))

        t = threading.Thread(target=do_final_lookup)
        t.start()

    def open_submit_popup():
        """
        Opens a redesigned popup dialog for submitting single or bulk IOCs for analysis.
        The layout is organized into logical groups, and the urlscan.io visibility
        options are dynamically shown or hidden based on the checkbox state.
        """
        popup = tk.Toplevel(root)
        popup.title("Submit Indicator for Analysis")
        popup.configure(bg="#F0F0F0")
        popup.resizable(False, False) # Prevent resizing for a cleaner look

        # Main container with padding
        container = tk.Frame(popup, bg="#F0F0F0", padx=20, pady=15)
        container.pack(fill="both", expand=True)

        # --- Variables ---
        mode_var = tk.StringVar(value="url")
        vt_var = tk.BooleanVar(value=True)
        urlscan_var = tk.BooleanVar(value=True)
        visibility_var = tk.StringVar(value="public")
        file_path_var = tk.StringVar()
        url_entry_var = tk.StringVar()
        bulk_csv_var = tk.StringVar()

        # --- Title ---
        lbl_title = tk.Label(
            container,
            text="Submit Indicator for Analysis",
            font=("Segoe UI", 16, "bold"),
            bg="#F0F0F0"
        )
        lbl_title.pack(pady=(0, 15), anchor="center")

        # --- Section 1: Submission Type ---
        mode_frame = ttk.LabelFrame(
            container,
            text="Submission Type",
            style="Bold.TLabelframe"
        )
        mode_frame.pack(fill="x", expand=True, pady=(0, 10))

        rb_url = ttk.Radiobutton(mode_frame, text="Single Domain/URL", variable=mode_var, value="url")
        rb_url.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        rb_file = ttk.Radiobutton(mode_frame, text="Single File", variable=mode_var, value="file")
        rb_file.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        rb_bulk = ttk.Radiobutton(mode_frame, text="Bulk IOCs (from .txt file)", variable=mode_var, value="bulk")
        rb_bulk.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        # --- Section 2: Input Fields (dynamically shown) ---
        input_frame = tk.Frame(container, bg="#F0F0F0")
        input_frame.pack(fill="x", expand=True, pady=(0, 10))
        input_frame.grid_columnconfigure(1, weight=1) # Allow entry to expand

        # Widgets for URL input
        lbl_url = ttk.Label(input_frame, text="URL:", font=FONT_LABEL)
        entry_url = ttk.Entry(input_frame, textvariable=url_entry_var, width=60, font=FONT_LABEL)

        # Widgets for File input
        lbl_file = ttk.Label(input_frame, text="File Path:", font=FONT_LABEL)
        entry_file = ttk.Entry(input_frame, textvariable=file_path_var, width=50, font=FONT_LABEL, state="readonly")
        browse_btn_file = ttk.Button(input_frame, text="Browse...")

        # Widgets for Bulk input
        lbl_bulk = ttk.Label(input_frame, text="File Path:", font=FONT_LABEL)
        entry_bulk = ttk.Entry(input_frame, textvariable=bulk_csv_var, width=50, font=FONT_LABEL, state="readonly")
        browse_btn_bulk = ttk.Button(input_frame, text="Browse...")

        # --- Section 3: API Options ---
        options_frame = ttk.LabelFrame(
            container,
            text="Analysis Options",
            style="Bold.TLabelframe"
        )
        options_frame.pack(fill="x", expand=True, pady=(0, 10))

        cb_vt = ttk.Checkbutton(options_frame, text="Submit to VirusTotal", variable=vt_var)
        cb_vt.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        cb_urlscan = ttk.Checkbutton(options_frame, text="Submit to urlscan.io", variable=urlscan_var)
        cb_urlscan.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # --- Section 4: urlscan.io Visibility (dynamically shown) ---
        visibility_frame = ttk.LabelFrame(
            container,
            text="urlscan.io Visibility",
            style="Bold.TLabelframe"
        )
        # Note: This frame is packed/unpacked dynamically by update_visibility_ui()

        rb_pub = ttk.Radiobutton(visibility_frame, text="Public", variable=visibility_var, value="public")
        rb_pub.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        rb_priv = ttk.Radiobutton(visibility_frame, text="Private (API Key Required)", variable=visibility_var, value="private")
        rb_priv.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # --- Section 5: Submit Button ---
        button_frame = tk.Frame(container, bg="#F0F0F0")
        button_frame.pack(fill="x", pady=(15, 0))

        submit_btn = tk.Button(
            button_frame,
            text="Submit Now",
            bg="#6A5ACD", # A nice shade of purple
            fg="white",
            font=("Segoe UI", 12, "bold"),
            relief="raised",
            borderwidth=2,
            width=15,
            padx=10,
            pady=5
        )
        submit_btn.pack(side="right") # Anchor button to the right

        # --- Helper Functions and Bindings ---

        def browse_single_file():
            path = filedialog.askopenfilename(parent=popup)
            if path:
                file_path_var.set(path)
            popup.lift()
        browse_btn_file.config(command=browse_single_file)

        def browse_bulk_csv():
            path = filedialog.askopenfilename(
                parent=popup,
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if path:
                bulk_csv_var.set(path)
            popup.lift()
        browse_btn_bulk.config(command=browse_bulk_csv)

        def hide_all_inputs():
            for widget in input_frame.winfo_children():
                widget.grid_remove()

        def update_visibility_ui(*args):
            # Show the visibility options only if urlscan is checked AND enabled
            if urlscan_var.get() and cb_urlscan['state'] == 'normal':
                visibility_frame.pack(fill="x", expand=True, pady=(0, 10))
            else:
                visibility_frame.pack_forget()

        def update_mode_ui(*args):
            hide_all_inputs()
            submission_type = mode_var.get()
            
            if submission_type == "url":
                lbl_url.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
                entry_url.grid(row=0, column=1, pady=5, sticky="ew")
                cb_urlscan.config(state='normal')
            elif submission_type == "file":
                lbl_file.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
                entry_file.grid(row=0, column=1, pady=5, sticky="ew")
                browse_btn_file.grid(row=0, column=2, padx=(5, 0), pady=5, sticky="w")
                # urlscan.io does not support file submission
                cb_urlscan.config(state='disabled')
                urlscan_var.set(False) 
            elif submission_type == "bulk":
                lbl_bulk.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
                entry_bulk.grid(row=0, column=1, pady=5, sticky="ew")
                browse_btn_bulk.grid(row=0, column=2, padx=(5, 0), pady=5, sticky="w")
                cb_urlscan.config(state='normal')

            update_visibility_ui() # Update visibility when mode changes

        # Bindings to update the UI dynamically
        mode_var.trace_add("write", update_mode_ui)
        urlscan_var.trace_add("write", update_visibility_ui)

        # Initial UI state setup
        update_mode_ui()

        def do_submit():
            submission_type = mode_var.get()
            do_vt = vt_var.get()
            do_us = urlscan_var.get()
            vis = visibility_var.get()

            if not (do_vt or do_us):
                messagebox.showerror("Error", "Select at least one service (VT/urlscan) to submit to.", parent=popup)
                return

            if submission_type == "url":
                ioc_to_submit = url_entry_var.get().strip()
                if not ioc_to_submit:
                    messagebox.showerror("Error", "Please enter a URL.", parent=popup)
                    return
                popup.destroy()
                results_q = queue.Queue()
                threading.Thread(
                    target=submit_indicator_logic_robust,
                    args=(ioc_to_submit, "url", do_vt, do_us, vis, results_q),
                    daemon=True
                ).start()
                progress_bar.start(10)
                status_bar.config(text="Submitting single Domain/URL for analysis...")
                root.after(100, check_submit_results, results_q)

            elif submission_type == "file":
                file_to_submit = file_path_var.get().strip()
                if not file_to_submit:
                    messagebox.showerror("Error", "Please pick a local file to submit.", parent=popup)
                    return
                popup.destroy()
                results_q = queue.Queue()
                threading.Thread(
                    target=submit_indicator_logic_robust,
                    args=(file_to_submit, "file", do_vt, do_us, vis, results_q),
                    daemon=True
                ).start()
                progress_bar.start(10)
                status_bar.config(text="Submitting single local file for analysis...")
                root.after(100, check_submit_results, results_q)

            elif submission_type == "bulk":
                bulk_file = bulk_csv_var.get().strip()
                if not bulk_file:
                    messagebox.showerror("Error", "Please select a file containing IOCs.", parent=popup)
                    return
                
                try:
                    with open(bulk_file, "r", encoding="utf-8") as f:
                        raw = f.read()
                except Exception as e:
                    messagebox.showerror("File Error", f"Could not read the file:\n{e}", parent=popup)
                    return

                popup.destroy()
                
                # Split on newlines, commas, or spaces, and filter out empty strings
                tokens = [item.strip() for item in re.split(r'[,\s\n]+', raw) if item.strip()]

                if not tokens:
                    messagebox.showwarning("Warning", "No valid IOCs found in the selected file.")
                    return

                results_q = queue.Queue()

                def worker_bulk():
                    for val in tokens:
                        try:

                            ioc_type_ = validate_ioc(val)
                            
                            single_item_q = queue.Queue()
                            process_iocs_with_selective_apis(
                                ioc_iterable=[val],
                                use_vt=vt_var.get(),
                                use_us=urlscan_var.get(),
                                use_validin=(ioc_type_ in ("domain", "ip_address")),
                                results_queue=single_item_q
                            )
                            result = single_item_q.get()
                            results_q.put(result)
                        except ValueError:
                            results_q.put((val, "unknown", None, [], f"Invalid or unsupported IOC format: {val}"))
                        except Exception as ex2:
                            results_q.put((val, "unknown", None, [], f"Error processing '{val}': {ex2}"))
                
                threading.Thread(target=worker_bulk, daemon=True).start()
                
                progress_bar.start(10)
                status_bar.config(text=f"Processing {len(tokens)} IOCs from file...")
                check_submit_file_results.processed_so_far = 0
                root.after(100, check_submit_file_results, results_q, len(tokens))

        submit_btn.config(command=do_submit)


    def check_submit_results(results_queue):
        """
        For the 'Submit' button. After the submission + final process_iocs is done,
        one result is expected => show the new row, or error, etc.
        """
        try:
            result = results_queue.get_nowait()

            # Debug logging
            print(f"DEBUG check_submit_results: result type={type(result)}, len={len(result)}")
            if len(result) > 0:
                print(f"DEBUG: result[0] = {result[0]}, type={type(result[0])}")

            # result should be either (ioc_str, ioc_type, parsed_data, sources, error)
            # or (ioc_str, ioc_type, parsed_data, sources) if no error
            if len(result) == 5:
                ioc_str, ioc_type, parsed_data, sources, error = result
            else:
                ioc_str, ioc_type, parsed_data, sources = result
                error = None

            # Ensure ioc_str is a string
            if isinstance(ioc_str, dict):
                # This shouldn't happen, but handle it gracefully
                print(f"ERROR: ioc_str is a dict: {ioc_str}")
                if 'url' in ioc_str:
                    ioc_str = ioc_str['url']
                elif 'value' in ioc_str:
                    ioc_str = ioc_str['value']
                else:
                    ioc_str = str(ioc_str.get('url', ioc_str.get('value', 'Unknown')))
            
            ioc_str = str(ioc_str).strip()  # Force to string
            
            # Check for JSON/dict contamination in the string
            if any(x in ioc_str for x in ['{', '[', '"http_response_data"', '"reputation"', 'Last Final URL']):
                print(f"ERROR: Submission IOC contains JSON/dict elements: {ioc_str[:100]}...")
                # Try to extract URL from the contaminated string
                import re
                url_match = re.search(r'https?://[^\s\'"{}]+', ioc_str)
                if url_match:
                    ioc_str = url_match.group(0)
                    print(f"Extracted clean URL: {ioc_str}")
                else:
                    # Try to extract SHA256 if it's a file
                    sha_match = re.search(r'[a-fA-F0-9]{64}', ioc_str)
                    if sha_match:
                        ioc_str = sha_match.group(0)
                        print(f"Extracted SHA256: {ioc_str}")
                    else:
                        print(f"Could not extract clean IOC from: {ioc_str}")
                        ioc_str = "Invalid IOC"

            progress_bar.stop()

            if error:
                # Display the error as a popup
                messagebox.showerror("Error", error)
            else:
                # If success, store the parsed_data in our response_cache
                if parsed_data and ioc_str and ioc_str != "Invalid IOC":  # Ensure we have a valid string key
                    response_cache[ioc_str] = {
                        "type": ioc_type,
                        "sources": sources,
                        "data": parsed_data
                    }
                    new_item = tree.insert("", "end", values=(ioc_str, ", ".join(sources)))

                    # If malicious vendors, color it
                    vm = parsed_data.get("vendors_marked_malicious")
                    if vm and "/" in vm:
                        left, right = vm.split("/")
                        try:
                            if int(left) > 0:
                                tree.item(new_item, tags=("malicious",))
                        except:
                            pass

                    status_bar.config(text=f"Submitted scan results for '{ioc_str}'.")
                    messagebox.showinfo("Submission Completed", f"The scan for '{ioc_str}' is complete.")
                else:
                    if ioc_str == "Invalid IOC":
                        messagebox.showwarning("Submission Issue", 
                            "The submission completed but the IOC format was corrupted. Please try searching for the IOC manually.")
                    else:
                        messagebox.showinfo("Submission Completed", f"The scan returned no data.")

        except queue.Empty:
            # No result yet => check again in 100ms
            root.after(100, check_submit_results, results_queue)



    def open_api_key_popup() -> None:
            """
            Popup for setting API keys, redesigned for clarity and consistent button placement.
            """
            popup = tk.Toplevel(root)
            popup.title("Configure API Keys")
            popup.configure(bg="#F0F0F0")
            # popup.geometry("500x420")  # REMOVED: This was the cause of the problem.
            popup.resizable(False, False)
            
            container = tk.Frame(popup, bg="#F0F0F0", padx=15, pady=15)
            container.pack(fill="both", expand=True)

            lbl_title = tk.Label(
                container, text="Configure API Keys", font=("Segoe UI", 14, "bold"), bg="#F0F0F0"
            )
            lbl_title.pack(pady=(0, 15))

            # --- VirusTotal Section ---
            vt_frame = tk.LabelFrame(container, text="VirusTotal", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
            vt_frame.pack(fill="x", pady=5)
            tk.Label(vt_frame, text="API Key:", bg="#F0F0F0", font=FONT_LABEL).pack(anchor="w")
            vt_entry = tk.Entry(vt_frame, width=50, show="*")
            vt_entry.pack(fill="x", pady=(2, 5))
            if config.VT_API_KEY:
                tk.Label(vt_frame, text="(An existing key is already set. Entering a new key will overwrite it.)",
                        fg="darkred", font=("Segoe UI", 9, "italic"), bg="#F0F0F0", wraplength=400).pack(anchor="w")

            # --- urlscan.io Section ---
            st_frame = tk.LabelFrame(container, text="urlscan.io", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
            st_frame.pack(fill="x", pady=5)
            tk.Label(st_frame, text="API Key:", bg="#F0F0F0", font=FONT_LABEL).pack(anchor="w")
            st_entry = tk.Entry(st_frame, width=50, show="*")
            st_entry.pack(fill="x", pady=(2, 5))
            if config.URLSCAN_API_KEY:
                tk.Label(st_frame, text="(An existing key is already set. Entering a new key will overwrite it.)",
                        fg="darkred", font=("Segoe UI", 9, "italic"), bg="#F0F0F0", wraplength=400).pack(anchor="w")

            # --- Validin Section ---
            val_frame = tk.LabelFrame(container, text="Validin", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
            val_frame.pack(fill="x", pady=5)
            tk.Label(val_frame, text="API Key:", bg="#F0F0F0", font=FONT_LABEL).pack(anchor="w")
            validin_entry = tk.Entry(val_frame, width=50, show="*")
            validin_entry.pack(fill="x", pady=(2, 5))
            if config.VALIDIN_API_KEY:
                tk.Label(val_frame, text="(An existing key is already set. Entering a new key will overwrite it.)",
                        fg="darkred", font=("Segoe UI", 9, "italic"), bg="#F0F0F0", wraplength=400).pack(anchor="w")

            # --- Button Frame and Apply Button ---
            def apply_api_keys():
                """Encrypt and persist keys, then clear cached clients."""
                keys_to_persist = {}
                vt_key = vt_entry.get().strip()
                us_key = st_entry.get().strip()
                va_key = validin_entry.get().strip()

                if vt_key:
                    keys_to_persist["vt"] = encrypt_string(vt_key)
                if us_key:
                    keys_to_persist["urlscan"] = encrypt_string(us_key)
                if va_key:
                    keys_to_persist["validin"] = encrypt_string(va_key)

                if keys_to_persist:
                    persist_api_keys(**keys_to_persist)
                    
                    # After saving new keys, we must clear the old, "stale"
                    # API clients from the processor. This forces the app to
                    # create new clients with the correct keys on the next API call.
                    _proc._VT_CLIENT = None
                    _proc._US_CLIENT = None
                    _proc._VA_CLIENT = None

                    messagebox.showinfo(
                        "Success", "API keys have been encrypted and saved.", parent=popup
                    )

                popup.destroy()

            # Create a dedicated frame for the button
            button_frame = tk.Frame(container, bg="#F0F0F0")
            button_frame.pack(fill="x", pady=(20, 0))

            apply_btn = tk.Button(
                button_frame,
                text="Apply & Save",
                command=apply_api_keys,
                bg="#6A5ACD",
                fg="white",
                font=("Segoe UI", 11, "bold"),
                relief="raised",
                width=15,
                pady=2
            )
            apply_btn.pack(side="right")


    def open_screenshot_popup(scan_id):
        """
        Retrieve https://urlscan.io/screenshots/<scan_id>.png
        Display a scrollable screenshot with a Save button at the top.
        """

        url = f"https://urlscan.io/screenshots/{scan_id}.png"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                # Convert raw bytes -> PIL Image
                image_data = BytesIO(resp.content)
                pil_img = Image.open(image_data).convert("RGB")

                # Create the popup
                popup = tk.Toplevel()
                popup.title(f"Screenshot for scan ID {scan_id}")
                popup.geometry("900x600")
                popup.configure(bg="white")

                # ------------------------------------------------------------------
                # 1) CREATE A "TOOLBAR" FRAME AT THE TOP FOR BUTTONS
                # ------------------------------------------------------------------
                toolbar = tk.Frame(popup, bg="#ECECEC")
                toolbar.pack(side="top", fill="x")

                def save_image():
                    """
                    Prompt investigator for a filename, then save the PNG out.
                    """
                    path = filedialog.asksaveasfilename(
                        defaultextension=".png",
                        filetypes=[("PNG Files", "*.png")],
                        title="Save Screenshot"
                    )
                    if path:
                        try:
                            pil_img.save(path, "PNG")
                            messagebox.showinfo("Saved", f"Screenshot saved to:\n{path}")
                        except Exception as e:
                            messagebox.showerror("Error", f"Could not save image:\n{e}")

                save_btn = tk.Button(
                    toolbar,
                    text="Save Image",
                    command=save_image,
                    bg="#6A5ACD",
                    fg="white",
                    relief="raised"
                )
                save_btn.pack(side="left", padx=8, pady=5)

                def close_popup():
                    popup.destroy()

                # ------------------------------------------------------------------
                # 2) SCROLLABLE CANVAS FOR THE IMAGE
                # ------------------------------------------------------------------
                canvas_frame = tk.Frame(popup, bg="white")
                canvas_frame.pack(side="top", fill="both", expand=True)

                canvas = tk.Canvas(canvas_frame, bg="white")
                h_scroll = tk.Scrollbar(canvas_frame, orient="horizontal", command=canvas.xview)
                v_scroll = tk.Scrollbar(canvas_frame, orient="vertical",   command=canvas.yview)
                canvas.configure(xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)

                h_scroll.pack(side="bottom", fill="x")
                v_scroll.pack(side="right", fill="y")
                canvas.pack(side="left", fill="both", expand=True)

                # Create a frame inside the canvas to hold the Label
                image_frame = tk.Frame(canvas, bg="white")
                frame_id = canvas.create_window((0, 0), window=image_frame, anchor="nw")

                # Convert PIL -> Tkinter Image and place in a Label
                tk_img = ImageTk.PhotoImage(pil_img)
                lbl = tk.Label(image_frame, image=tk_img, bg="white")
                lbl.image = tk_img  # keep reference
                lbl.pack()

                # Auto-scroll region
                def on_configure(event):
                    canvas.configure(scrollregion=canvas.bbox("all"))
                image_frame.bind("<Configure>", on_configure)

            elif resp.status_code == 404:
                messagebox.showinfo("Not Found", f"No screenshot found for scan ID {scan_id}")
            else:
                messagebox.showerror("Error", f"HTTP {resp.status_code} retrieving screenshot")
        except Exception as e:
            messagebox.showerror("Error", f"Failed retrieving screenshot: {e}")

    def open_dom_popup(scan_id):
        """
        Retrieves https://urlscan.io/dom/<scan_id>/
        Displays the DOM in a scrolled Text widget with a "Copy DOM" button
        at the top so the investigator can easily copy the entire DOM content.
        """

        url = f"https://urlscan.io/dom/{scan_id}/"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                dom_text = resp.text

                # Create the popup window
                popup = tk.Toplevel()
                popup.title(f"DOM for {scan_id}")
                popup.geometry("900x600") 
                popup.configure(bg="white")

                # ---------------------------------------------------------
                # 1) CREATE A TOOLBAR FOR THE 'COPY DOM' BUTTON
                # ---------------------------------------------------------
                toolbar = tk.Frame(popup, bg="#ECECEC")
                toolbar.pack(side="top", fill="x")

                text_widget = None

                def copy_dom():
                    """
                    Copies the entire DOM text to the system clipboard.
                    """
                    if text_widget is not None:
                        all_text = text_widget.get("1.0", "end-1c")
                        popup.clipboard_clear()
                        popup.clipboard_append(all_text)
                        popup.update()  
                        messagebox.showinfo("Copied", "The DOM text has been copied to your clipboard.")
                
                copy_btn = tk.Button(
                    toolbar,
                    text="Copy DOM",
                    command=copy_dom,
                    bg="#6A5ACD",
                    fg="white",
                    relief="raised"
                )
                copy_btn.pack(side="left", padx=8, pady=5)

                # ---------------------------------------------------------
                # 2) CREATE A SCROLLABLE TEXT WIDGET BELOW THE TOOLBAR
                # ---------------------------------------------------------
                text_frame = tk.Frame(popup, bg="white")
                text_frame.pack(side="top", fill="both", expand=True)

                v_scroll = tk.Scrollbar(text_frame, orient="vertical")
                h_scroll = tk.Scrollbar(text_frame, orient="horizontal")
                text_box = tk.Text(
                    text_frame,
                    wrap="none",  # Horizontal scrolling for lines
                    yscrollcommand=v_scroll.set,
                    xscrollcommand=h_scroll.set
                )
                text_widget = text_box 

                v_scroll.config(command=text_box.yview)
                v_scroll.pack(side="right", fill="y")

                h_scroll.config(command=text_box.xview)
                h_scroll.pack(side="bottom", fill="x")

                text_box.pack(side="left", fill="both", expand=True)
                
                # Insert the DOM text
                text_box.insert("1.0", dom_text)

            elif resp.status_code == 404:
                messagebox.showinfo("Not Found", f"No DOM snapshot for scan ID {scan_id}")
            else:
                messagebox.showerror("Error", f"HTTP {resp.status_code} retrieving DOM.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed retrieving DOM: {e}")

    def search_single_api(ioc_str, use_vt=False, use_us=False, use_validin=False):
        """
        Search a single API for the given IOC.
        """
        try:
            ioc_type_ = validate_ioc(ioc_str)
        except ValueError:
            messagebox.showerror("Error", f"'{ioc_str}' is not a valid IOC format.")
            return

        api_name = ""
        if use_vt:
            api_name = "VirusTotal"
        elif use_us:
            api_name = "URLScan.io"
        elif use_validin:
            api_name = "Validin"

        local_q = queue.Queue()

        def worker():
            process_iocs_with_selective_apis(
                ioc_iterable=[ioc_str],
                use_vt=use_vt,
                use_us=use_us,
                use_validin=use_validin,
                results_queue=local_q
            )

        t = threading.Thread(target=worker)
        t.start()

        def check_results():
            try:
                result = local_q.get_nowait()
                
                # Debug logging
                print(f"DEBUG check_results: received result type={type(result)}, len={len(result)}")
                if len(result) > 0:
                    print(f"DEBUG: result[0] (IOC) = {result[0]}, type={type(result[0])}")
                
                # Process result
                if len(result) == 5:
                    found_ioc, found_type, found_data, found_srcs, found_err = result
                else:
                    found_ioc, found_type, found_data, found_srcs = result
                    found_err = None

                # Validate and clean the IOC
                if isinstance(found_ioc, dict):
                    print(f"ERROR: found_ioc is a dict: {found_ioc}")
                    # Try to extract the actual IOC from the dict
                    if 'url' in found_ioc:
                        found_ioc = found_ioc['url']
                    elif 'value' in found_ioc:
                        found_ioc = found_ioc['value']
                    else:
                        found_ioc = str(ioc_str)  # Fall back to original
                
                # Ensure it's a string
                found_ioc = str(found_ioc).strip()
                
                # Check if it contains JSON/dict elements
                if any(x in found_ioc for x in ['{', '[', '"reputation"', '"http_response"', 'Last Final URL']):
                    print(f"ERROR: IOC contains data structure elements: {found_ioc[:100]}...")
                    # This is wrong - use the original ioc_str instead
                    found_ioc = ioc_str

                progress_bar.stop()

                if found_err:
                    messagebox.showerror("Error", found_err)
                    status_bar.config(text=f"Error from {api_name}: {found_err}")
                    return

                if found_data:
                    response_cache[found_ioc] = {
                        "type": found_type,
                        "sources": found_srcs,
                        "data": found_data
                    }
                    new_item = tree.insert("", "end",
                                        values=(found_ioc, ", ".join(found_srcs)))
                    vm = found_data.get("vendors_marked_malicious")
                    if vm and "/" in vm:
                        left, right = vm.split("/")
                        try:
                            if int(left) > 0:
                                tree.item(new_item, tags=("malicious",))
                        except:
                            pass
                    status_bar.config(text=f"{api_name} search: Inserted '{found_ioc}'.")
                else:
                    messagebox.showinfo("Search Result", f"No data returned for '{ioc_str}' from {api_name}.")

            except queue.Empty:
                root.after(100, check_results)
                return

        progress_bar.start(10)
        status_bar.config(text=f"Searching {api_name} for '{ioc_str}' ...")
        root.after(100, check_results)

    def bind_treeview_right_click_menu(tv: ttk.Treeview):
        """
        Binds an enhanced right-click context menu to 'tv' with improved organization
        and granular API control.
        """
        menu = tk.Menu(tv, tearoff=0)
        selected_cell_value = [None]
        selected_row_values = [None]

        def do_popup(event):
            row_id = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)

            if not row_id or not col_id:
                return

            tv.selection_set(row_id)

            column_index = int(col_id.replace('#','')) - 1
            row_values = tv.item(row_id, "values")
            selected_row_values[0] = row_values

            if 0 <= column_index < len(row_values):
                cell_val = row_values[column_index]
            else:
                cell_val = None

            selected_cell_value[0] = cell_val
            
            # Clear the menu and rebuild it
            menu.delete(0, tk.END)
            build_menu()
            
            menu.post(event.x_root, event.y_root)

        tv.bind("<Button-3>", do_popup)

        def build_menu():
            # Basic copy operations
            menu.add_command(label="Copy Indicator", command=copy_indicator)
            menu.add_command(label="Copy Row", command=copy_row)
            menu.add_separator()
            
            # Search APIs submenu
            search_menu = tk.Menu(menu, tearoff=0)
            search_menu.add_command(label="Search All Available APIs", command=search_all_apis_command)
            search_menu.add_separator()
            search_menu.add_command(label="VirusTotal", command=search_virustotal_only)
            search_menu.add_command(label="URLScan.io", command=search_urlscan_only)
            search_menu.add_command(label="Validin", command=search_validin_only)
            menu.add_cascade(label="Search APIs", menu=search_menu)
            
            # Pivot submenu
            pivot_menu = tk.Menu(menu, tearoff=0)
            pivot_menu.add_command(label="Hunt Resource Hash (URLScan)", command=pivot_resource_hash_command)
            
            # Validin hash category submenu
            validin_hash_menu = tk.Menu(pivot_menu, tearoff=0)
            validin_hash_menu.add_command(label="JARM", command=lambda: search_validin_hash_category("JARM"))
            validin_hash_menu.add_command(label="Certificate SHA256", command=lambda: search_validin_hash_category("CERT_FINGERPRINT_SHA256"))
            validin_hash_menu.add_command(label="Body SHA1", command=lambda: search_validin_hash_category("BODY_SHA1"))
            validin_hash_menu.add_command(label="Header Hash", command=lambda: search_validin_hash_category("HEADER_HASH"))
            validin_hash_menu.add_command(label="Banner Hash", command=lambda: search_validin_hash_category("BANNER_0_HASH"))
            validin_hash_menu.add_command(label="Favicon Hash", command=lambda: search_validin_hash_category("FAVICON_HASH"))
            pivot_menu.add_cascade(label="Search Hash by Category (Validin)", menu=validin_hash_menu)
            
            menu.add_cascade(label="Pivot", menu=pivot_menu)
            
            # Collect submenu
            collect_menu = tk.Menu(menu, tearoff=0)
            collect_menu.add_command(label="Website Screenshot (URLScan)", command=collect_screenshot_command)
            collect_menu.add_command(label="Website DOM (URLScan)", command=collect_dom_command)
            collect_menu.add_command(label="HTTP Response Headers", command=collect_headers_command)
            menu.add_cascade(label="Collect", menu=collect_menu)
            
            # External lookups submenu
            external_menu = tk.Menu(menu, tearoff=0)
            external_menu.add_command(label="Google Search", command=google_search_command)
            external_menu.add_command(label="Shodan", command=shodan_search_command)
            external_menu.add_command(label="Censys", command=censys_search_command)
            external_menu.add_command(label="AbuseIPDB", command=abuseipdb_search_command)
            menu.add_cascade(label="External Lookups", menu=external_menu)

        # Command implementations
        def copy_indicator():
            val = selected_cell_value[0]
            if not val:
                return
            tv.clipboard_clear()
            tv.clipboard_append(val)

        def copy_row():
            vals = selected_row_values[0]
            if not vals:
                return
            row_text = "\t".join(str(v) for v in vals)
            tv.clipboard_clear()
            tv.clipboard_append(row_text)

        def search_all_apis_command():
            val = selected_cell_value[0]
            if not val:
                return
            pivot_single_ioc_for_all_apis(val)

        def search_virustotal_only():
            val = selected_cell_value[0]
            if not val:
                return
            search_single_api(val, use_vt=True, use_us=False, use_validin=False)

        def search_urlscan_only():
            val = selected_cell_value[0]
            if not val:
                return
            search_single_api(val, use_vt=False, use_us=True, use_validin=False)

        def search_validin_only():
            val = selected_cell_value[0]
            if not val:
                return
            search_single_api(val, use_vt=False, use_us=False, use_validin=True)

        def pivot_resource_hash_command():
            val = selected_cell_value[0]
            if not val:
                return
            pivot_resource_hash(val)

        def search_validin_hash_category(category):
            val = selected_cell_value[0]
            if not val:
                return
            # This would use the category-specific endpoint
            messagebox.showinfo("Hash Category Search", 
                f"Searching Validin for {category} hash: {val}\n(Not implemented yet)")

        def collect_screenshot_command():
            val = selected_cell_value[0]
            if not val:
                return
            if not re.match(r'^[0-9a-fA-F-]{36}$', val):
                messagebox.showerror("Error", f"'{val}' doesn't look like a urlscan scan ID.")
                return
            open_screenshot_popup(val)

        def collect_dom_command():
            val = selected_cell_value[0]
            if not val:
                return
            if not re.match(r'^[0-9a-fA-F-]{36}$', val):
                messagebox.showerror("Error", f"'{val}' doesn't look like a urlscan scan ID.")
                return
            open_dom_popup(val)

        def collect_headers_command():
            val = selected_cell_value[0]
            if not val:
                return
            messagebox.showinfo("Collect Headers", f"Collecting headers for: {val}\n(Not implemented yet)")

        def google_search_command():
            val = selected_cell_value[0]
            if not val:
                return
            import urllib.parse
            webbrowser.open(f"https://www.google.com/search?q={urllib.parse.quote(val)}")

        def shodan_search_command():
            val = selected_cell_value[0]
            if not val:
                return
            webbrowser.open(f"https://www.shodan.io/search?query={val}")

        def censys_search_command():
            val = selected_cell_value[0]
            if not val:
                return
            webbrowser.open(f"https://search.censys.io/search?resource=hosts&q={val}")

        def abuseipdb_search_command():
            val = selected_cell_value[0]
            if not val:
                return
            # Check if it's an IP
            ip_re = r"^(?:\d{1,3}\.){3}\d{1,3}$"
            if re.match(ip_re, val):
                webbrowser.open(f"https://www.abuseipdb.com/check/{val}")
            else:
                messagebox.showinfo("Info", "AbuseIPDB only supports IP address lookups")

    def reorder_sources(sources_list):
        """
        Reorder sources so that if both VirusTotal API and SecurityTrails API
        are present, VirusTotal API appears first.
        """
        # Convert to a list in normal Python order.
        seen = []
        for s in sources_list:
            if s not in seen:
                seen.append(s)
        # Now do the forced reorder:
        reordered = []
        # Always place VirusTotal first if present
        if "VirusTotal API" in seen:
            reordered.append("VirusTotal API")
        # Next place SecurityTrails if present
        if "SecurityTrails API" in seen:
            reordered.append("SecurityTrails API")
        # Then place any other items
        for s in seen:
            if s not in reordered:
                reordered.append(s)
        return reordered

    def pivot_resource_hash(ioc_hash):
        # Simple redirect to urlscan (no scraping)
        pivot_bodyhash_search(ioc_hash)


    def pivot_single_ioc_for_all_apis(ioc_str):
        """
        1) Validate the ioc_str,
        2) spawn a background thread that calls process_iocs_with_selective_apis,
        3) parse results and insert into the tree with proper error handling.
        """
        try:
            ioc_type_ = validate_ioc(ioc_str)
        except ValueError:
            messagebox.showerror("Error", f"'{ioc_str}' is not a valid domain, IP, URL, or file hash.")
            return

        local_q = queue.Queue()

        def worker():
            # Use the same selective API processing that handles errors gracefully
            process_iocs_with_selective_apis(
                ioc_iterable=[ioc_str],
                use_vt=True,
                use_us=True,
                use_validin=(ioc_type_ in ("domain", "ip_address", "fingerprint_hash")),
                results_queue=local_q
            )

        t = threading.Thread(target=worker)
        t.start()

        # Use the same check_results function that handles partial results
        progress_bar.start(10)
        status_bar.config(text=f"Searching all APIs for '{ioc_str}' ...")
        root.after(100, lambda: check_results_with_context(local_q, "Search All APIs"))

    def check_results_with_context(results_queue, context="Search"):
        """
        Modified check_results that includes context in messages
        """
        try:
            result = results_queue.get_nowait()
        except queue.Empty:
            root.after(100, check_results_with_context, results_queue, context)
            return

        # Parse the tuple
        if len(result) == 5:
            ioc_, ioc_type_, parsed_data, sources_, error_ = result
        else:
            ioc_, ioc_type_, parsed_data, sources_ = result
            error_ = None

        # Check if we have data despite errors
        has_data = bool(parsed_data)
        has_errors = bool(error_)
        
        if has_data:
            # Add to cache and tree
            response_cache[ioc_] = {
                "type": ioc_type_,
                "sources": sources_,
                "data": parsed_data
            }

            malicious_count = 0
            vm = parsed_data.get("vendors_marked_malicious") if parsed_data else None
            if vm and isinstance(vm, str) and "/" in vm:
                try:
                    left, right = vm.split("/")
                    malicious_count = int(left)
                except:
                    pass

            sources_ = reorder_sources(sources_)
            joined_sources = ", ".join(sources_)
            new_item = tree.insert("", "end", values=(ioc_, joined_sources))
            if malicious_count > 0:
                tree.item(new_item, tags=("malicious",))

            # Update row colors
            children = tree.get_children()
            for idx, item_id in enumerate(children):
                tag = "oddrow" if (idx % 2) else "evenrow"
                existing_tags = tree.item(item_id, "tags")
                if "malicious" in existing_tags:
                    tree.item(item_id, tags=(tag, "malicious"))
                else:
                    tree.item(item_id, tags=(tag,))

            if has_errors:
                # Parse which APIs failed
                failed_apis = []
                if "VirusTotal Error:" in error_ or "VT quota exceeded" in error_:
                    failed_apis.append("VirusTotal")
                if "urlscan" in error_.lower():
                    failed_apis.append("URLScan.io")
                if "validin" in error_.lower():
                    failed_apis.append("Validin")
                
                if not failed_apis and error_:
                    failed_apis.append("Unknown API")
                
                failed_str = ", ".join(failed_apis) if failed_apis else "some APIs"
                status_bar.config(text=f"{context}: '{ioc_}' added (partial results - {failed_str} unavailable)")
                
                messagebox.showinfo(
                    f"{context} - Partial Results", 
                    f"{context} completed with partial results for '{ioc_}'.\n\n"
                    f"The following APIs were unavailable:\n{chr(10).join('• ' + api for api in failed_apis)}\n\n"
                    "Results from available APIs have been added."
                )
            else:
                status_bar.config(text=f"{context}: '{ioc_}' added successfully.")
        else:
            if has_errors:
                messagebox.showerror(f"{context} Failed", f"No results found for '{ioc_}'.\n\nErrors:\n{error_}")
                status_bar.config(text=f"{context} failed for '{ioc_}'")
            else:
                messagebox.showinfo("No Results", f"No data found for IOC '{ioc_}' in any API.")
                status_bar.config(text=f"No results found for '{ioc_}'")
        
        progress_bar.stop()

    def check_results(results_queue):
        """
        Periodically checks the 'results_queue' for the next
        (ioc_str, ioc_type, parsed_data, sources_list, error_str) result.
        Updates the main Treeview + status bar, or displays an error popup
        if error_str is present. Never kills the mainloop.
        """
        try:
            # 1) Get a result immediately
            result = results_queue.get_nowait()
        except queue.Empty:
            # If the queue is empty, schedule another check in 100ms
            root.after(100, check_results, results_queue)
            return

        # 2) Parse the tuple
        if len(result) == 5:
            ioc_, ioc_type_, parsed_data, sources_, error_ = result
        else:
            ioc_, ioc_type_, parsed_data, sources_ = result
            error_ = None

        # 3) NCheck if we have data despite errors
        has_data = bool(parsed_data)
        has_errors = bool(error_)
        
        # 4) Handle different scenarios
        if has_data:
            # We have data, so add it to the tree regardless of errors
            response_cache[ioc_] = {
                "type": ioc_type_,
                "sources": sources_,
                "data": parsed_data
            }

            malicious_count = 0
            vm = parsed_data.get("vendors_marked_malicious") if parsed_data else None
            if vm and isinstance(vm, str) and "/" in vm:
                try:
                    left, right = vm.split("/")
                    malicious_count = int(left)
                except:
                    pass

            # Reorder sources, insert new row:
            sources_ = reorder_sources(sources_)
            joined_sources = ", ".join(sources_)
            new_item = tree.insert("", "end", values=(ioc_, joined_sources))
            if malicious_count > 0:
                tree.item(new_item, tags=("malicious",))

            children = tree.get_children()
            for idx, item_id in enumerate(children):
                tag = "oddrow" if (idx % 2) else "evenrow"
                existing_tags = tree.item(item_id, "tags")
                if "malicious" in existing_tags:
                    tree.item(item_id, tags=(tag, "malicious"))
                else:
                    tree.item(item_id, tags=(tag,))

            # Show appropriate status message
            if has_errors:
                # We have data but some APIs failed - show warning
                # Parse the error to extract which APIs failed
                failed_apis = []
                if "VirusTotal Error:" in error_ or "VT quota exceeded" in error_:
                    failed_apis.append("VirusTotal")
                if "urlscan.io Error:" in error_ or "urlscan" in error_.lower():
                    failed_apis.append("URLScan.io")
                if "Validin Error:" in error_ or "validin" in error_.lower():
                    failed_apis.append("Validin")
                
                # If we couldn't parse specific APIs, show generic message
                if not failed_apis and error_:
                    failed_apis.append("Unknown API")
                
                failed_str = ", ".join(failed_apis) if failed_apis else "some APIs"
                status_bar.config(text=f"IOC '{ioc_}' added (partial results - {failed_str} unavailable)")
                
                # Show info message about partial results
                messagebox.showinfo(
                    "Partial Results", 
                    f"Search completed with partial results for '{ioc_}'.\n\n"
                    f"The following APIs were unavailable:\n{chr(10).join('• ' + api for api in failed_apis)}\n\n"
                    "Results from available APIs have been added."
                )
            else:
                # Complete success
                status_bar.config(text=f"IOC '{ioc_}' added successfully.")
        
        else:
            # No data at all
            if has_errors:
                # Show error since we got nothing
                messagebox.showerror("Search Failed", f"No results found for '{ioc_}'.\n\nErrors:\n{error_}")
                status_bar.config(text=f"Search failed for '{ioc_}'")
            else:
                # No data and no errors - IOC not found
                messagebox.showinfo("No Results", f"No data found for IOC '{ioc_}' in any of the selected APIs.")
                status_bar.config(text=f"No results found for '{ioc_}'")
        
        # 5) Stop progress bar
        progress_bar.stop()

        # 6) Check if the queue is still non-empty => keep draining
        if not results_queue.empty():
            root.after(100, check_results, results_queue)


            

    def check_submit_file_results(results_queue, total_count):
        """
        Similar to check_results_file_upload, but for submissions.
        This will keep popping from the queue until we've processed 'total_count' results.
        Each item in the queue is either:
        (ioc_str, ioc_type, parsed_data, sources_list, err)
        or (ioc_str, ioc_type, parsed_data, sources_list) if no error.
        """
        processed_this_call = 0

        try:
            while True: # Loop to process all items currently in the queue
                result = results_queue.get_nowait()
                processed_this_call += 1

                ioc_str, ioc_type, parsed_data, sources, err = None, None, None, [], None # Initialize defaults

                # Robustly unpack the result
                if isinstance(result, tuple) and 4 <= len(result) <= 5:
                    if len(result) == 5:
                        ioc_str, ioc_type, parsed_data, sources, err = result
                    else: # len(result) == 4
                        ioc_str, ioc_type, parsed_data, sources = result
                        err = None # Explicitly set err to None
                else:
                    # Handle malformed result
                    # Log this unexpected format for debugging
                    print(f"Error: Received unexpected result format in check_submit_file_results: {result}")
                    if isinstance(result, tuple) and len(result) > 0:
                        ioc_str_attempt = str(result[0])[:100] # Get first element as potential IOC
                    else:
                        ioc_str_attempt = "Unknown IOC"
                    
                    ioc_str = ioc_str_attempt
                    ioc_type = "unknown" # Default type for malformed result
                    parsed_data = None
                    sources = []
                    err = f"Malformed result from processing queue for '{ioc_str_attempt}'."


                if ioc_type is None:
                    ioc_type = "unknown"
                if sources is None:
                    sources = []
                if ioc_str is None: # Should ideally not happen if unpacking is robust
                    ioc_str = "Unknown IOC (processing error)"


                if err:
                    # Show the error in a popup
                    messagebox.showerror("Error Processing Submission", f"IOC '{clean_ioc_for_display(ioc_str)}': {err}")
                else:
                    # If success, add to the main Treeview
                    if parsed_data: 
                        response_cache[ioc_str] = {
                            "type": ioc_type,
                            "sources": sources,
                            "data": parsed_data
                        }
                        
                        # Reorder sources before displaying
                        ordered_sources = reorder_sources(sources) # Assuming reorder_sources is defined
                        new_item = tree.insert("", "end", values=(ioc_str, ", ".join(ordered_sources)))

                        # If malicious vendors, color it
                        vm = parsed_data.get("vendors_marked_malicious")
                        if vm and isinstance(vm, str) and "/" in vm: # Check type of vm
                            left, right = vm.split("/")
                            try:
                                if int(left) > 0:
                                    tree.item(new_item, tags=("malicious",))
                            except ValueError: # Handle case where split parts aren't ints
                                pass
                        status_bar.config(text=f"Submitted '{clean_ioc_for_display(ioc_str)}' successfully and added to results.")
                    else:
                        # If no actual data was parsed, but no error string, it could be an IOC not found
                        # or a submission that yielded no new info. Add to tree with fewer details.
                        ordered_sources = reorder_sources(sources)
                        tree.insert("", "end", values=(ioc_str, ", ".join(ordered_sources))) # Add even if no parsed_data to show it was processed
                        status_bar.config(text=f"Submission for '{clean_ioc_for_display(ioc_str)}' processed; no new data or already cached.")


                # Re-stripe row colors after each insertion
                children = tree.get_children()
                for idx, item_id in enumerate(children):
                    tag = 'oddrow' if (idx % 2) else 'evenrow'
                    existing_tags = list(tree.item(item_id, "tags")) # Convert to list
                    
                    if 'oddrow' in existing_tags: existing_tags.remove('oddrow')
                    if 'evenrow' in existing_tags: existing_tags.remove('evenrow')
                    

                    final_tags = [tag] + existing_tags # Prepend striping tag
                    tree.item(item_id, tags=tuple(final_tags))


        except queue.Empty:
            pass

        # Update the static attribute that tracks total processed items
        check_submit_file_results.processed_so_far += processed_this_call
        
        if check_submit_file_results.processed_so_far >= total_count:
            progress_bar.stop()
            messagebox.showinfo("Submission Completed", f"Finished processing {check_submit_file_results.processed_so_far}/{total_count} submitted IOCs.")
            status_bar.config(text=f"Finished processing {check_submit_file_results.processed_so_far} submitted IOCs.")
            check_submit_file_results.processed_so_far = 0 # Reset for next bulk operation
        else:
            status_bar.config(text=f"Processing submissions... {check_submit_file_results.processed_so_far}/{total_count}")
            root.after(100, check_submit_file_results, results_queue, total_count)

    if not hasattr(check_submit_file_results, 'processed_so_far'):
        check_submit_file_results.processed_so_far = 0


    check_submit_file_results.processed_so_far = 0

    def check_results_file_upload(results_queue, total_count, all_errors: list):
        """
        Periodically checks the results queue, updates the GUI in real-time,
        and collects any non-blocking errors for a final summary.
        """
        try:
            while True: 
                result = results_queue.get_nowait()
                check_results_file_upload.processed_so_far += 1
                
                ioc_, ioc_type_, parsed_data, sources_, error_ = result

                if error_:
                    all_errors.append(f"IOC '{ioc_}': {error_}")
                
                if parsed_data:
                    response_cache[ioc_] = {
                        "type": ioc_type_,
                        "sources": sources_,
                        "data": parsed_data
                    }
                    malicious_count = 0
                    vm = parsed_data.get("vendors_marked_malicious")
                    if vm and isinstance(vm, str) and "/" in vm:
                        try:
                            malicious_count = int(vm.split('/')[0])
                        except (ValueError, IndexError):
                            pass
                    
                    sources_ = reorder_sources(sources_)
                    joined_sources = ", ".join(sources_)
                    new_item = tree.insert("", "end", values=(ioc_, joined_sources))

                    if malicious_count > 0:
                        tree.item(new_item, tags=("malicious",))

                    status_bar.config(text=f"IOC '{ioc_}' added successfully.")

        except queue.Empty:
            pass

        status_bar.config(text=f"Processing {check_results_file_upload.processed_so_far}/{total_count}...")

        children = tree.get_children()
        for idx, item_id in enumerate(children):
            tag = 'oddrow' if (idx % 2) else 'evenrow'
            existing_tags = tree.item(item_id, "tags")
            if "malicious" in existing_tags:
                tree.item(item_id, tags=(tag, "malicious"))
            else:
                tree.item(item_id, tags=(tag,))

        if check_results_file_upload.processed_so_far >= total_count:
            progress_bar.stop()
            status_bar.config(text=f"Bulk search complete. Processed {total_count} IOCs.")

            if all_errors:
                error_message = (
                    "The search completed with the following non-blocking errors:\n\n"
                    + "\n".join(all_errors)
                )
                messagebox.showwarning("Partial Search Errors", error_message)
            else:
                messagebox.showinfo("Completed", f"Successfully processed {total_count} IOCs.")

            check_results_file_upload.processed_so_far = 0
            return  # Stop the recurring 'after' calls

        else:
            root.after(100, check_results_file_upload, results_queue, total_count, all_errors)

    def open_search_popup():
        """
        Popup for single IOC search, redesigned for clarity and consistency.
        """
        popup = tk.Toplevel(root)
        popup.title("Indicator Search")
        popup.configure(bg="#F0F0F0")
        popup.resizable(False, False)

        container = tk.Frame(popup, bg="#F0F0F0", padx=15, pady=15)
        container.pack(fill="both", expand=True)

        lbl_title = tk.Label(
            container, text="Search for an Indicator", font=("Segoe UI", 14, "bold"), bg="#F0F0F0"
        )
        lbl_title.pack(pady=(0, 15))

        # --- IOC Input Frame ---
        input_frame = tk.LabelFrame(container, text="Indicator", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
        input_frame.pack(fill="x", pady=5)
        ioc_var = tk.StringVar()
        entry_ioc = tk.Entry(input_frame, width=50, textvariable=ioc_var)
        entry_ioc.pack(fill="x")
        entry_ioc.focus_set()

        # --- API Selection Frame ---
        api_frame = tk.LabelFrame(container, text="Data Sources", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
        api_frame.pack(fill="x", pady=5)
        api_checkbox_frame = tk.Frame(api_frame, bg="#F0F0F0") # Inner frame for centering
        api_checkbox_frame.pack()
        
        vt_var = tk.BooleanVar(value=True)
        us_var = tk.BooleanVar(value=True)
        val_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(api_checkbox_frame, text="VirusTotal", variable=vt_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)
        tk.Checkbutton(api_checkbox_frame, text="urlscan.io", variable=us_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)
        tk.Checkbutton(api_checkbox_frame, text="Validin (Domain/IP/Response Hashes)", variable=val_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)

        # --- Action Buttons ---
        btn_frame = tk.Frame(container, bg="#F0F0F0")
        btn_frame.pack(fill="x", pady=(20, 0))

        def do_search():
            ioc_str = ioc_var.get().strip()
            use_vt = vt_var.get()
            use_us = us_var.get()
            use_val = val_var.get()
            
            # Add debug print
            print(f"\nDEBUG Search: IOC='{ioc_str}', VT={use_vt}, US={use_us}, Validin={use_val}")
            
            if not (use_vt or use_us or use_val):
                messagebox.showerror("Error", "Select at least one API.")
                return
            if not ioc_str:
                messagebox.showerror("Error", "Please enter an IOC to search.")
                return
            
            # Validate IOC type to ensure proper API selection
            try:
                ioc_type = validate_ioc(ioc_str)
                print(f"DEBUG: Detected IOC type: {ioc_type}")
                
                # For fingerprint hashes, ensure Validin is selected
                if ioc_type == "fingerprint_hash" and not use_val:
                    messagebox.showinfo("Info", "Fingerprint hashes are only supported by Validin. Enabling Validin API.")
                    use_val = True
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                return
            
            results_q = queue.Queue()
            def worker():
                process_iocs_with_selective_apis(
                    [ioc_str], 
                    use_vt=use_vt, 
                    use_us=use_us, 
                    use_validin=use_val, 
                    results_queue=results_q
                )
            threading.Thread(target=worker, daemon=True).start()
            popup.destroy()
            progress_bar.start(10)
            status_bar.config(text=f"Searching '{clean_ioc_for_display(ioc_str)}' ...")
            root.after(100, check_results, results_q)

        search_btn = tk.Button(
            btn_frame, text="Search Now", command=do_search, bg="#6A5ACD", fg="white",
            font=("Segoe UI", 11, "bold"), relief="raised", width=15
        )
        search_btn.pack(side="right")

    def open_upload_popup():
        """
        Opens a popup for bulk IOC search from a file, with a standardized UI design
        and a new configurable delay slider for rate limiting.
        """
        popup = tk.Toplevel(root)
        popup.title("Bulk Indicator Search")
        popup.configure(bg="#F0F0F0")
        popup.resizable(False, False)

        container = tk.Frame(popup, bg="#F0F0F0", padx=15, pady=15)
        container.pack(fill="both", expand=True)

        lbl_title = tk.Label(
            container, text="Bulk Indicator Search", font=("Segoe UI", 14, "bold"), bg="#F0F0F0"
        )
        lbl_title.pack(pady=(0, 15))


        file_frame = tk.LabelFrame(container, text="Source File", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
        file_frame.pack(fill="x", pady=5)
        tk.Label(file_frame, text="Select a .txt file with one IOC per line:", bg="#F0F0F0", font=FONT_LABEL).pack(anchor="w", pady=(0,5))
        
        file_path_var = tk.StringVar()
        entry_file_frame = tk.Frame(file_frame, bg="#F0F0F0")
        entry_file_frame.pack(fill="x")
        entry_file = tk.Entry(entry_file_frame, textvariable=file_path_var, width=40)
        entry_file.pack(side="left", fill="x", expand=True)
        entry_file.focus_set()
        
        def browse_file():
            path = filedialog.askopenfilename(parent=popup, filetypes=[("Text Files", "*.txt")], title="Select IOC text file")
            if path:
                file_path_var.set(path)

        browse_btn = tk.Button(entry_file_frame, text="Browse...", bg="#9370DB", fg="#FFFFFF", font=FONT_BUTTON, command=browse_file)
        browse_btn.pack(side="left", padx=(5,0))


        api_frame = tk.LabelFrame(container, text="Data Sources", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
        api_frame.pack(fill="x", pady=5)
        api_checkbox_frame = tk.Frame(api_frame, bg="#F0F0F0")
        api_checkbox_frame.pack()
        
        vt_var = tk.BooleanVar(value=True)
        urlscan_var = tk.BooleanVar(value=True)
        val_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(api_checkbox_frame, text="VirusTotal", variable=vt_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)
        tk.Checkbutton(api_checkbox_frame, text="urlscan.io", variable=urlscan_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)
        tk.Checkbutton(api_checkbox_frame, text="Validin (Domain/IP/Response Hashes)", variable=val_var, bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=10)


        delay_frame = tk.LabelFrame(container, text="API Rate Limit Delay", font=("Segoe UI", 11, "bold"), bg="#F0F0F0", padx=10, pady=10)
        delay_frame.pack(fill="x", pady=5)
        delay_var = tk.DoubleVar(value=1.0) # Default to 1 second

        tk.Label(delay_frame, text="Delay between IOCs (seconds):", bg="#F0F0F0", font=FONT_LABEL).pack(side="left", padx=(0, 10))
        
        delay_slider = tk.Scale(
            delay_frame,
            from_=0.0,
            to=5.0,
            orient="horizontal",
            variable=delay_var,
            resolution=0.1, # Allow for tenths of a second
            length=200,     
            bg="#F0F0F0",
            troughcolor='#BDC3C7',
            highlightthickness=0
        )
        delay_slider.pack(side="left", fill="x", expand=True)
        
        current_delay_label = tk.Label(delay_frame, textvariable=delay_var, width=4, bg="#F0F0F0", font=FONT_LABEL)
        current_delay_label.pack(side="left", padx=(5,0))

        # --- Action Button ---
        btn_frame = tk.Frame(container, bg="#F0F0F0")
        btn_frame.pack(fill="x", pady=(20, 0))

        def do_bulk_search():
            chosen_file = file_path_var.get().strip()
            if not chosen_file:
                messagebox.showerror("Error", "Please select a .txt file containing IOCs.")
                return

            use_vt = vt_var.get()
            use_us = urlscan_var.get()
            use_val = val_var.get()

            if not (use_vt or use_us or use_val):
                messagebox.showerror("Error", "Select at least one API to use.")
                return

            selected_delay = delay_var.get()

            try:
                with open(chosen_file, "r", encoding="utf-8") as f:
                    raw_lines = (line.strip() for line in f)
                    lines = [line.rstrip(",") for line in raw_lines if line and line.rstrip(",")]
            except Exception as e:
                messagebox.showerror("Error Reading File", f"Could not read the selected file:\n{e}")
                return

            if not lines:
                messagebox.showwarning("Warning", "No valid lines found in file.")
                return

            popup.destroy()

            results_q = queue.Queue()
            all_errors = []

            def worker():
                # --- Pass the new delay value to the processor ---
                process_iocs_with_selective_apis(
                    ioc_iterable=lines,
                    use_vt=use_vt,
                    use_us=use_us,
                    use_validin=use_val,
                    results_queue=results_q,
                    delay_seconds=selected_delay 
                )

            t = threading.Thread(target=worker, daemon=True)
            t.start()

            progress_bar.start(10)
            check_results_file_upload.processed_so_far = 0
            root.after(100, check_results_file_upload, results_q, len(lines), all_errors)

        go_btn = tk.Button(
            btn_frame, text="Search Now", command=do_bulk_search, bg="#6A5ACD", fg="white",
            font=("Segoe UI", 11, "bold"), relief="raised", width=15
        )
        go_btn.pack(side="right")



    def export_to_csv():
        """
        Exports all currently cached IOC data to a CSV file chosen by the user,
        but uses a more robust schema optimized for pivoting. Each IOC becomes
        one row, with grouped columns:
        - Indicator, Indicator Type, Sources
        - Network IPs, Network Domains, Network URLs
        - Host File Paths, Host Registry Keys, Host Command Lines
        - File MD5, File SHA1, File SHA256
        - Threat Actors, Malware Families, MITRE ATT&CK TTPs, YARA Rules, CVEs
        """
        if not response_cache:
            messagebox.showerror("Error", "No IOCs to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files","*.csv")],
            title="Save CSV"
        )
        if not file_path:
            return


        # Define the CSV columns in logical, grouped order
        basic_fields = [
            "Indicator", "Indicator Type", "Sources"
        ]
        network_fields = [
            "Network IPs", "Network Domains", "Network URLs"
        ]
        host_fields = [
            "Host File Paths", "Host Registry Keys", "Host Command Lines"
        ]
        file_fields = [
            "File MD5", "File SHA1", "File SHA256"
        ]
        context_fields = [
            "Threat Actors", "Malware Families", "MITRE ATT&CK TTPs",
            "YARA Rules", "CVEs"
        ]

        fieldnames = (
            basic_fields
            + network_fields
            + host_fields
            + file_fields
            + context_fields
        )

        # Open the CSV for writing
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()

                # Go through each cached IOC and build one row
                for ioc_str, ioc_content in response_cache.items():
                    # Robustness Check: Ensure ioc_content is a dictionary
                    if not isinstance(ioc_content, dict):
                        print(f"Skipping IOC {ioc_str}: ioc_content is not a dictionary.")
                        continue

                    ioc_type_val = ioc_content.get("type", "unknown") 
                    sources_list = ioc_content.get("sources", [])
                    if not isinstance(sources_list, list): 
                        sources_list = []

                    parsed_data = ioc_content.get("data") 


                    if not isinstance(parsed_data, dict):
                        print(f"Skipping IOC {ioc_str}: parsed_data is not a dictionary (type: {type(parsed_data)}).")
                        parsed_data = {} # Treat as empty if not a dict to avoid further errors

                    row = {}
                    # 1) Basic fields
                    row["Indicator"] = ioc_str
                    row["Indicator Type"] = ioc_type_val
                    row["Sources"] = "; ".join(sources_list)

                    # 2a) NETWORK indicators (IPs, Domains, URLs)
                    all_ips = []
                    all_domains = []
                    all_urls = []

                    # Robustness Check for relationships
                    rels = parsed_data.get("relationships", {})
                    if isinstance(rels, dict): 
                        contacted_items = rels.get("Contacted Items", [])
                        if isinstance(contacted_items, list): 
                            for cobj in contacted_items:
                                if isinstance(cobj, dict):
                                    itype = cobj.get("indicator_type", "").lower()
                                    val = cobj.get("value", "")
                                    if itype == "ip":
                                        all_ips.append(val)
                                    elif itype == "domain":
                                        all_domains.append(val)
                                    elif itype == "url":
                                        all_urls.append(val)
                                else:
                                    print(f"Warning for IOC {ioc_str}: Item in 'Contacted Items' is not a dict: {cobj}")
                        else:
                             print(f"Warning for IOC {ioc_str}: 'Contacted Items' is not a list: {contacted_items}")
                    else:
                        print(f"Warning for IOC {ioc_str}: 'relationships' is not a dict: {rels}")


                    outgoing_links = parsed_data.get("outgoing_links", [])
                    if isinstance(outgoing_links, list): 
                        for link in outgoing_links:
                            all_urls.append(str(link))
                    else:
                        print(f"Warning for IOC {ioc_str}: 'outgoing_links' is not a list: {outgoing_links}")

                    all_ips = list(set(all_ips))
                    all_domains = list(set(all_domains))
                    all_urls = list(set(all_urls))

                    row["Network IPs"] = "; ".join(all_ips)
                    row["Network Domains"] = "; ".join(all_domains)
                    row["Network URLs"] = "; ".join(all_urls)

                    # 2b) HOST indicators: file paths, registry keys, command lines
                    host_file_paths = []
                    host_registry_keys = []
                    host_command_lines = []

                    # Robustness Check for dynamic_analysis
                    dynamic_analysis = parsed_data.get("dynamic_analysis", {})
                    if isinstance(dynamic_analysis, dict): 
                        bh_details = dynamic_analysis.get("behavior_summary_details", {})
                        if isinstance(bh_details, dict): 
                            files_written = bh_details.get("files_written", [])
                            if isinstance(files_written, list):
                                for fw_item in files_written:
                                    if isinstance(fw_item, dict): 
                                        host_file_paths.append(fw_item.get("file_path",""))
                                    else:
                                        print(f"Warning for IOC {ioc_str}: Item in 'files_written' is not a dict: {fw_item}")
                            else:
                                print(f"Warning for IOC {ioc_str}: 'files_written' is not a list: {files_written}")

                            reg_opened = bh_details.get("registry_keys_opened", [])
                            if isinstance(reg_opened, list):
                                for rk in reg_opened:
                                    if isinstance(rk, str):
                                        host_registry_keys.append(rk)
                                    else:
                                        print(f"Warning for IOC {ioc_str}: Item in 'registry_keys_opened' is not a string: {rk}")
                            else:
                                print(f"Warning for IOC {ioc_str}: 'registry_keys_opened' is not a list: {reg_opened}")

                            cmd_execs = bh_details.get("command_executions", [])
                            if isinstance(cmd_execs, list):
                                for cmd in cmd_execs:
                                    host_command_lines.append(str(cmd)) 
                            else:
                                print(f"Warning for IOC {ioc_str}: 'command_executions' is not a list: {cmd_execs}")
                        else:
                            print(f"Warning for IOC {ioc_str}: 'behavior_summary_details' is not a dict: {bh_details}")
                    else:
                        print(f"Warning for IOC {ioc_str}: 'dynamic_analysis' is not a dict: {dynamic_analysis}")

                    host_file_paths = list(set(filter(None, host_file_paths)))
                    host_registry_keys = list(set(filter(None, host_registry_keys)))
                    host_command_lines = list(set(filter(None, host_command_lines)))

                    row["Host File Paths"] = "; ".join(host_file_paths)
                    row["Host Registry Keys"] = "; ".join(host_registry_keys)
                    row["Host Command Lines"] = "; ".join(host_command_lines)

                    # 2c) File hashes
                    file_md5 = parsed_data.get("md5", "")
                    file_sha1 = parsed_data.get("sha1", "")
                    file_sha256 = parsed_data.get("sha256", "")

                    if not any([file_md5, file_sha1, file_sha256]):
                        # Check rels (already checked if it's a dict)
                        if isinstance(rels, dict):
                            related_hashes = rels.get("Related Files", [])
                            if isinstance(related_hashes, list):
                                sha256_list = []
                                for rh in related_hashes:
                                    if isinstance(rh, dict) and "sha256" in rh: 
                                        sha256_list.append(rh["sha256"])
                                file_sha256 = "; ".join(sha256_list)
                            else:
                                print(f"Warning for IOC {ioc_str}: 'Related Files' is not a list: {related_hashes}")

                    row["File MD5"] = str(file_md5) 
                    row["File SHA1"] = str(file_sha1) 
                    row["File SHA256"] = str(file_sha256) 

                    # 2d) THREAT CONTEXT fields
                    threat_actors = []
                    malware_families = []
                    mitre_ttps = []
                    yara_rules = []
                    cves = []

                    # Check dynamic_analysis (already checked if it's a dict)
                    if isinstance(dynamic_analysis, dict):
                        sigma_list = dynamic_analysis.get("sigma_analysis_results", [])
                        if isinstance(sigma_list, list): 
                            for sigma_item in sigma_list:
                                # Placeholder for actual TTP/YARA parsing from sigma_item if applicable
                                pass
                        else:
                            print(f"Warning for IOC {ioc_str}: 'sigma_analysis_results' is not a list: {sigma_list}")

                        sbv_list = dynamic_analysis.get("sandbox_verdicts", [])
                        if isinstance(sbv_list, list): 
                            for sbv in sbv_list:
                                if isinstance(sbv, dict): 
                                    mal_list = sbv.get("malware_names", [])
                                    if isinstance(mal_list, list): 
                                        for mn in mal_list:
                                            malware_families.append(str(mn)) 
                                    else:
                                        print(f"Warning for IOC {ioc_str}: 'malware_names' in sandbox_verdicts is not a list: {mal_list}")
                                else:
                                    print(f"Warning for IOC {ioc_str}: Item in 'sandbox_verdicts' is not a dict: {sbv}")
                        else:
                            print(f"Warning for IOC {ioc_str}: 'sandbox_verdicts' is not a list: {sbv_list}")

                    threat_actors = list(set(threat_actors))
                    malware_families = list(set(malware_families))
                    mitre_ttps = list(set(mitre_ttps))
                    yara_rules = list(set(yara_rules))
                    cves = list(set(cves))

                    row["Threat Actors"] = "; ".join(threat_actors)
                    row["Malware Families"] = "; ".join(malware_families)
                    row["MITRE ATT&CK TTPs"] = "; ".join(mitre_ttps)
                    row["YARA Rules"] = "; ".join(yara_rules)
                    row["CVEs"] = "; ".join(cves)

                    writer.writerow(row)

            messagebox.showinfo("Success", f"Exported pivot-friendly CSV:\n{file_path}")
            status_bar.config(text=f"Exported pivot-friendly CSV to {file_path}")

        except Exception as ex:
            messagebox.showerror("Error", f"An unexpected error occurred during CSV export: {str(ex)}")
            status_bar.config(text=f"Error exporting to CSV: {ex}")


    # ------------------------------------------------------------------------
    # 4a) UI DRAWING METHODS
    # ------------------------------------------------------------------------
    def create_subfield_box(parent, key, val, bg_color):
        rename_map = {
            "last_final_url": "Last Final URL",
            "last_http_response_content_length": "Last HTTP Response Content Length",
            "last_http_response_code": "Last HTTP Response Code",
            "redirection_chain": "Redirection Chain",
            "last_dns_records": "Last DNS Records",
            "last_http_response_headers": "Certificate Details",
            "categories": "Categories"
        }
        display_key = rename_map.get(key, key)

        field_frame = tk.LabelFrame(
            parent,
            text=display_key,
            font=("Segoe UI", 12, "bold"),
            bg=bg_color,
            fg=TEXT_COLOR,
            padx=10,
            pady=10
        )
        field_frame.pack(fill="x", padx=5, pady=5)

        # Categories => specialized table
        if key == "categories" and isinstance(val, dict):
            create_treeview_for_categories(field_frame, val)
            return

        # last_dns_records => specialized table
        if key == "last_dns_records" or display_key == "Last DNS Records":
            if isinstance(val, list):
                create_treeview_for_dns_records(field_frame, val)
            else:
                create_textbox_with_scroll(
                    field_frame,
                    str(val),
                    "#FFFFFF",
                    FONT_TREE,
                    60,
                    4,
                    include_copy_button=True
                )
            return

        # last_http_response_headers => certificate details
        if key == "last_http_response_headers" or display_key == "Certificate Details":
            if isinstance(val, dict):
                create_certificate_details_tree(field_frame, val)
            else:
                create_textbox_with_scroll(
                    field_frame,
                    str(val),
                    "#FFFFFF",
                    FONT_TREE,
                    60,
                    4,
                    include_copy_button=True
                )
            return

        # vendors / reputation => color-coded
        if display_key in ["Vendors Marked Malicious", "Reputation"]:
            try:
                if isinstance(val, str) and "/" in val:
                    numerator, denominator = map(int, val.split("/"))
                    color = "red" if numerator > 0 else "blue"
                else:
                    color = "red" if (isinstance(val, int) and val < 0) else "blue"
                font_style = ("Segoe UI", 10, "bold")
                lbl = tk.Label(field_frame, text=val, fg=color, bg=bg_color, font=font_style, anchor="w")
                lbl.pack(anchor="w", padx=5, pady=2)
            except:
                lbl = tk.Label(field_frame, text=val, fg="black", bg=bg_color, font=FONT_LABEL, anchor="w")
                lbl.pack(anchor="w", padx=5, pady=2)
            return

        # PE Metadata => single text-box table
        if key == "PE Metadata" and isinstance(val, dict):
            table_str = format_dictionary_as_table(val)
            create_textbox_with_scroll(
                field_frame,
                table_str,
                "#FFFFFF",
                FONT_TREE,
                60,
                6,
                include_copy_button=True
            )
            return

        # fallback

        if isinstance(val, str):
            display_val = val
        elif isinstance(val, list) and all(isinstance(x, str) for x in val):
            display_val = "\n".join(val)
        else:
            display_val = json.dumps(val, indent=2)

        lines = display_val.count("\n") + 1
        final_height = min(lines, 10)

        include_copy_btn = key != "Last VT Analysis Date"

        create_textbox_with_scroll(
            field_frame,
            display_val,
            "#FFFFFF",
            FONT_TREE,
            60,
            final_height,
            include_copy_button=include_copy_btn  
        )

    def create_textbox_with_scroll(
            parent,
            text_content,
            bg_color="#FFFFFF",
            font_style=("Helvetica", 9),
            width=60,
            height=5,
            include_copy_button=False
        ):
            # Overall container for the text widget and its button
            # The 'parent' is usually a LabelFrame for a specific section
            outer_container = tk.Frame(parent, bg=parent.cget("bg")) # Inherit parent's background
            outer_container.pack(fill="x", expand=True, pady=2)

            # Frame for the Text widget and its vertical scrollbar
            text_widget_frame = tk.Frame(outer_container, bg=parent.cget("bg"))
            text_widget_frame.pack(fill="both", expand=True) # This frame will contain the text and its VSB

            sb = tk.Scrollbar(text_widget_frame, orient="vertical") # Scrollbar inside text_widget_frame
            txt = tk.Text(
                text_widget_frame, # Text widget also inside text_widget_frame
                wrap="word",
                yscrollcommand=sb.set,
                bg=bg_color,
                font=font_style,
                width=width,
                height=height,
                bd=0, 
                highlightthickness=0
            )
            sb.config(command=txt.yview)
            sb.pack(side="right", fill="y")
            txt.pack(side="left", fill="both", expand=True)
            txt.insert("1.0", text_content)
            txt.configure(state="disabled") # Keep as normal if copying directly, or manage state around copy

            if include_copy_button:
                # Frame for the button, packed below the text_widget_frame
                button_frame = tk.Frame(outer_container, bg=parent.cget("bg"))
                button_frame.pack(side="bottom", anchor="sw", fill="x", pady=(2,0))

                def copy_to_clip():
                    content = txt.get("1.0", "end-1c")
                    # It's generally safer to use the root window for clipboard operations
                    # if 'root' is accessible globally or passed down.
                    # Assuming 'root' is the global Tk() instance.
                    try:
                        root_window = parent.winfo_toplevel() # Get the top-level window
                        root_window.clipboard_clear()
                        root_window.clipboard_append(content)
                        root_window.update() # Important for clipboard to update immediately
                        copy_btn.config(text="Copied!")
                        root_window.after(2000, lambda: copy_btn.config(text="Copy"))
                    except Exception as e:
                        print(f"Clipboard error: {e}") # Or show a small status to user
                        copy_btn.config(text="Failed!")
                        if 'root_window' in locals(): # Check if root_window was defined
                            root_window.after(2000, lambda: copy_btn.config(text="Copy"))
                        else: # Fallback if root_window couldn't be determined
                            parent.after(2000, lambda: copy_btn.config(text="Copy"))


                copy_btn = tk.Button(
                    button_frame,
                    text="Copy",
                    command=copy_to_clip,
                    bg=BUTTON_COLOR, 
                    fg="#FFFFFF",
                    font=FONT_BUTTON 
                )
                copy_btn.pack(side="left", padx=5, pady=(0,2))

            return txt
    
    def create_vertical_kv_tree(parent, kv_map: dict):
        """
        Displays each (key -> value) in a 2-column TreeView with right click menu functionality
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)
        
        columns = ("Field", "Value")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=len(kv_map))
        tv.heading("Field", text="Field", anchor="w")
        tv.heading("Value", text="Value", anchor="w")
        tv.column("Field", width=200, anchor="w", stretch=False)
        tv.column("Value", width=600, anchor="w", stretch=True)

        for field_name, field_value in kv_map.items():
            tv.insert("", "end", values=(field_name, field_value))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tv.pack(side="left", fill="both", expand=True)

        #Bind the right-click menu ---
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all():
            lines = [f"{row[0]}: {row[1]}" for row in (tv.item(row_id, "values") for row_id in tv.get_children())]
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            copy_btn.config(text="Copied!")
            parent.after(1500, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all)

    def create_ip_traffic_treeview(parent, ip_traffic_list):
        """Builds a multi-column Treeview for IP traffic."""
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)
        
        columns = ("Destination IP", "Destination Port", "Protocol")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Destination IP", text="Destination IP", anchor="w"); tv.column("Destination IP", width=200, anchor="w", stretch=True, minwidth=150)
        tv.heading("Destination Port", text="Destination Port", anchor="w"); tv.column("Destination Port", width=120, anchor="w", stretch=False, minwidth=80)
        tv.heading("Protocol", text="Protocol", anchor="w"); tv.column("Protocol", width=100, anchor="w", stretch=False, minwidth=80)

        if not ip_traffic_list:
            tv.insert("", "end", values=("No IP traffic data found.", "", ""))
        else:
            for item in ip_traffic_list:
                tv.insert("", "end", values=(item.get("destination_ip", ""), str(item.get("destination_port", "")), item.get("transport_layer_protocol", "")))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        return tv


    def create_services_started_treeview(parent, service_list):
        """Builds treeview for Services Started."""
        return build_single_column_treeview(parent, service_list, column_label="Service Name")

    def create_files_written_treeview(parent, file_list):
        """Builds treeview for Files Written."""
        return build_single_column_treeview(parent, file_list, column_label="File Path Written")

    def create_files_deleted_treeview(parent, file_list):
        """Builds treeview for Files Deleted."""
        return build_single_column_treeview(parent, file_list, column_label="File Path Deleted")

    def create_mutexes_created_treeview(parent, mutex_list):
        """Builds treeview for Mutexes Created."""
        return build_single_column_treeview(parent, mutex_list, column_label="Mutex Name")

    def create_calls_highlighted_treeview(parent, call_list):
        """Builds treeview for Highlighted Calls."""
        return build_single_column_treeview(parent, call_list, column_label="Highlighted Call")

    def create_http_conversations_treeview(parent, http_list):
        """Builds a multi-column Treeview for HTTP conversations."""
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("URL", "Method", "User-Agent")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=5)
        tv.heading("URL", text="URL", anchor="w"); tv.column("URL", width=500, anchor="w", stretch=True, minwidth=250)
        tv.heading("Method", text="Method", anchor="w"); tv.column("Method", width=80, anchor="w", stretch=False, minwidth=60)
        tv.heading("User-Agent", text="User-Agent", anchor="w"); tv.column("User-Agent", width=400, anchor="w", stretch=True, minwidth=200)

        if not http_list:
            tv.insert("", "end", values=("No HTTP conversations found.", "", ""))
        else:
            for item in http_list:
                headers = item.get("request_headers", {})
                user_agent = headers.get("User-Agent", "") if isinstance(headers, dict) else ""
                tv.insert("", "end", values=(item.get("url", ""), item.get("request_method", ""), user_agent))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        return tv
    
    def create_ja3_treeview(parent, ja3_list):
        """Builds a single-column Treeview for JA3 digests."""
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("JA3 Digest",)
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=4)
        tv.heading("JA3 Digest", text="JA3 Digest", anchor="w")
        tv.column("JA3 Digest", width=600, anchor="w", stretch=True, minwidth=300)

        if not ja3_list: tv.insert("", "end", values=("No JA3 digests found.",))
        else:
            for digest in ja3_list: tv.insert("", "end", values=(digest,))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        return tv

    def create_whois_subtrees(parent, whois_data: dict):
        """
        Creates 7 separate labeled frames for the WHOIS data:

        1) Registrar
        2) Registrant
        3) Date 
        4) Domain
        5) Administrative
        6) Technical
        7) Billing

        Each sub-frame calls create_vertical_kv_tree(...) 
        passing only the relevant key → value entries.

        Args:
            parent: A Tkinter frame in which to place these labeled frames
            whois_data: The dictionary result from parse_virustotal_whois(...)
        """

        bg_color = parent["bg"] if "bg" in parent.config() else "#F0F0F0"

        # 1) Registrar Info
        registrar_keys = [
            "Registrar",
            "Registrar IANA ID",
            "Registrar URL",
            "Registrar WHOIS Server",
            "Registrar Domain ID",
            "Registrar Abuse Contact Email",
            "Registrar Abuse Contact Phone",
            "Domain registrar id",
            "Domain registrar url",
        ]
        reg_dict = {}
        for k in registrar_keys:
            if k in whois_data:
                reg_dict[k] = whois_data[k]

        if reg_dict:
            lf = tk.LabelFrame(
                parent,
                text="Registrar",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf, reg_dict)

        # 2) Registrant Info
        registrant_keys = [
            "Registrant name",
            "Registrant email",
            "Registrant city",
            "Registrant country",
            "Registrant state",
            "Registrant fax",
            "Registrant phone",
            "Registrant zip",
            "Registrant organization",
            "Registrant street",
        ]
        regn_dict = {}
        for k in registrant_keys:
            if k in whois_data:
                regn_dict[k] = whois_data[k]

        if regn_dict:
            lf2 = tk.LabelFrame(
                parent,
                text="Registrant",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf2.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf2, regn_dict)

        # 3) Date Info
        date_keys = [
            "Create date",
            "Expiry date",
            "Update date",
            "Query time"
        ]
        dt_dict = {}
        for k in date_keys:
            if k in whois_data:
                dt_dict[k] = whois_data[k]

        if dt_dict:
            lf3 = tk.LabelFrame(
                parent,
                text="Date",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf3.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf3, dt_dict)

        # 4) Domain Info
        dom_keys = [
            "Domain name",
            "Domain Status",
            "DNSSEC",
            "Name server 1",
            "Name server 2",
            "Name server 3",
            "Name server 4",
            "Name server 5",
            "Name server 6",
            
        ]
        dm_dict = {}
        for k in dom_keys:
            if k in whois_data:
                dm_dict[k] = whois_data[k]

        if dm_dict:
            lf4 = tk.LabelFrame(
                parent,
                text="Domain",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf4.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf4, dm_dict)

        # 5) Administrative Info
        admin_keys = [
            "Administrative city",
            "Administrative country",
            "Administrative organization",
            "Administrative postal code",
            "Administrative state"
        ]
        ad_dict = {}
        for k in admin_keys:
            if k in whois_data:
                ad_dict[k] = whois_data[k]

        if ad_dict:
            lf5 = tk.LabelFrame(
                parent,
                text="Administrative",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf5.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf5, ad_dict)

        # 6) Technical Info
        tech_keys = [
            "Technical city",
            "Technical country",
            "Technical organization",
            "Technical postal code",
            "Technical state"
        ]
        tech_dict = {}
        for k in tech_keys:
            if k in whois_data:
                tech_dict[k] = whois_data[k]

        if tech_dict:
            lf6 = tk.LabelFrame(
                parent,
                text="Technical",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf6.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf6, tech_dict)

        # 7) Billing Info
        bill_keys = [
            "Billing city",
            "Billing country",
            "Billing organization",
            "Billing postal code",
            "Billing state"
        ]
        b_dict = {}
        for k in bill_keys:
            if k in whois_data:
                b_dict[k] = whois_data[k]

        if b_dict:
            lf7 = tk.LabelFrame(
                parent,
                text="Billing",
                font=("Segoe UI", 11, "bold"),
                bg=bg_color,
                fg="black",
                padx=10,
                pady=10
            )
            lf7.pack(fill="x", padx=5, pady=5)
            create_vertical_kv_tree(lf7, b_dict)

    def format_dictionary_as_table(mapping):
        if not mapping:
            return "No data"
        items = list(mapping.items())
        max_left = max(len(str(k)) for k, _ in items)
        lines = []
        for k, v in items:
            if isinstance(v, list):
                if len(v) == 0:
                    v_str = "not applicable"
                else:
                    v_str = ", ".join(str(x) for x in v)
            elif v is None or v == "":
                v_str = "not applicable"
            else:
                v_str = str(v)
            lines.append(f"{str(k):<{max_left}}  {v_str}")
        return "\n".join(lines)

    def create_certificate_details_tree(parent, cert_dict):
        """
        Displays VirusTotal certificate data in a single row with these columns:
        Key Usage, Extended Key Usage, Not Before Cert Date, Not After Cert Date,
        Cert Thumbprint - sha256, Subject Key Identifier, Subject Alternative Name,
        Cert Issuer Org
        """
        container = tk.Frame(parent, bg=BACKGROUND_COLOR)
        container.pack(fill="x", expand=True, pady=5)

        columns = (
            "Key Usage",
            "Extended Key Usage",
            "Not Before Cert Date",
            "Not After Cert Date",
            "Cert Thumbprint - sha256",
            "Subject Key Identifier",
            "Subject Alternative Name",
            "Cert Issuer Org"
        )

        tv = ttk.Treeview(container, columns=columns, show="headings", height=4)
        for i, col in enumerate(columns):
            tv.heading(col, text=col, anchor="w")
            if col == "Subject Alternative Name":
                tv.column(col, width=300, anchor="w", stretch=True, minwidth=200)
            elif col in ["Not Before Cert Date", "Not After Cert Date"]:
                tv.column(col, width=180, anchor="w", stretch=False, minwidth=150)
            elif col == "Cert Thumbprint - sha256":
                tv.column(col, width=400, anchor="w", stretch=False, minwidth=300)
            else:
                tv.column(col, width=200, anchor="w", stretch=False, minwidth=150)

        key_usage = cert_dict.get("key_usage", "")
        if isinstance(key_usage, list):
            key_usage = ", ".join(key_usage)
        extended_usage = cert_dict.get("extended_key_usage", "")
        if isinstance(extended_usage, list):
            extended_usage = ", ".join(extended_usage)

        not_before = cert_dict.get("not_before", "")
        not_after  = cert_dict.get("not_after", "")
        thumb_sha  = cert_dict.get("thumbprint_sha256", "")
        sub_key_id = cert_dict.get("subject_key_identifier", "")
        
        # Handle Subject Alternative Name
        alt_name   = cert_dict.get("subject_alternative_name", "")
        alt_name_list = []
        alt_name_display = ""
        
        if isinstance(alt_name, list):
            alt_name_list = alt_name
            if len(alt_name_list) > 1:
                alt_name_display = f"[{len(alt_name_list)} names] (double-click)"
            elif len(alt_name_list) == 1:
                alt_name_display = alt_name_list[0]
            else:
                alt_name_display = ""
        else:
            alt_name_display = str(alt_name) if alt_name else ""
        
        issuer_org = cert_dict.get("issuer_organization", "")

        item_id = tv.insert(
            "",
            "end",
            values=(
                key_usage,
                extended_usage,
                not_before,
                not_after,
                thumb_sha,
                sub_key_id,
                alt_name_display,
                issuer_org
            )
        )
        
        # Store the full data for popup
        item_data_map = {}
        if alt_name_list and len(alt_name_list) > 1:
            item_data_map[item_id] = {"alt_names": alt_name_list}
        
        # Add double-click handler
        def on_cert_double_click(event):
            item_id = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)
            
            if item_id in item_data_map and col_id == "#7":  # Column #7 is Subject Alternative Name
                show_match_data_popup("Subject Alternative Names", item_data_map[item_id]["alt_names"])
        
        tv.bind("<Double-1>", on_cert_double_click)

        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")

        tv.pack(side="top", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(container, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                row_vals = list(tv.item(child_id, "values"))
                # If this is the popup row, expand the alt names
                if child_id in item_data_map and "alt_names" in item_data_map[child_id]:
                    row_vals[6] = ", ".join(item_data_map[child_id]["alt_names"])
                lines.append("\t".join(str(v) for v in row_vals))
            joined_text = "\n".join(lines)

            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()

            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tv
    
    def create_graph_related_files_treeview(parent, file_list_from_graph):
            """
            Builds a Treeview for files found in graph relationships.
            Columns: SHA256, Type Tag.
            """
            container = tk.Frame(parent, bg=parent["bg"])
            container.pack(fill="both", expand=True, pady=5)

            columns = ("SHA256", "Type Tag")
            tv = ttk.Treeview(container, columns=columns, show="headings", height=6)
            tv.heading("SHA256", text="SHA256", anchor="w")
            tv.heading("Type Tag", text="Type Tag", anchor="w")

            tv.column("SHA256", width=450, anchor="w", stretch=False, minwidth=280)
            tv.column("Type Tag", width=150, anchor="w", stretch=True, minwidth=100)

            if not file_list_from_graph:
                tv.insert("", "end", values=("No related files found in graph.", ""))
            else:
                for file_item in file_list_from_graph:
                    sha256 = file_item.get("sha256", "")
                    type_tag = file_item.get("type_tag", "")
                    tv.insert("", "end", values=(sha256, type_tag))
            
            vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
            tv.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            hsb = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
            tv.configure(xscrollcommand=hsb.set)
            hsb.pack(side="bottom", fill="x")
            tv.pack(side="left", fill="both", expand=True)

            bind_treeview_right_click_menu(tv)

            btn_frame = tk.Frame(container, bg=parent["bg"]) # parent is container
            btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0)) 

            copy_btn = tk.Button(
                btn_frame, text="Copy All", bg="#9370DB", fg="white",
                font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
            )
            copy_btn.pack(side="left", padx=5)
            return tv
    
    def create_communicating_files_treeview(parent, filelike_items):
        """
        Creates treeview for 'Communicating/Referrer Files' with popups for 'Names', 'TRID',
        and dynamic analysis.
        """
        # This container holds ONLY the tree and its scrollbars for proper layout.
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        # --- Treeview setup ---
        columns = (
            "SHA256", "Type Tag", "Names", "Size", "Reputation",
            "TLSH", "SSDeep", "TRID", "Sigma (Count)", "Crowdsourced (Count)"
        )
        tree_comm = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        column_configs = {
            "SHA256": {"width": 280, "minwidth": 280, "stretch": False},
            "Type Tag": {"width": 80, "minwidth": 80, "stretch": False},
            "Names": {"width": 200, "minwidth": 150, "stretch": True},
            "Size": {"width": 80, "minwidth": 60, "stretch": False},
            "Reputation": {"width": 80, "minwidth": 70, "stretch": False},
            "TLSH": {"width": 200, "minwidth": 150, "stretch": False},
            "SSDeep": {"width": 200, "minwidth": 150, "stretch": False},
            "TRID": {"width": 150, "minwidth": 100, "stretch": True},
            "Sigma (Count)": {"width": 120, "minwidth": 100, "stretch": False},
            "Crowdsourced (Count)": {"width": 150, "minwidth": 120, "stretch": False}
        }
        for col, config in column_configs.items():
            tree_comm.heading(col, text=col, anchor="w")
            tree_comm.column(col, width=config["width"], anchor="w", stretch=config["stretch"], minwidth=config["minwidth"])

        # Popup Logic & Data Insertion ---
        item_data_map_comm = {}
        if not filelike_items:
            placeholder_values = ["No communicating files data."] + [""] * (len(columns) - 1)
            tree_comm.insert("", "end", values=tuple(placeholder_values))
        else:
            for item in filelike_items:
                # Prepare all row values
                sha256 = item.get("sha256", "")
                ttag = item.get("type_tag", "")
                size_val = str(item.get("size", ""))
                rep = str(item.get("reputation", ""))
                tlsh = item.get("tlsh", "")
                ssd = item.get("ssdeep", "")
                dynamic_analysis = item.get("dynamic_analysis", {})
                sigma_results = dynamic_analysis.get("sigma_analysis_results", [])
                csc_results = dynamic_analysis.get("crowdsourced_ids_results", [])
                sigma_count_str = f"[{len(sigma_results)} matches]"
                csc_count_str = f"[{len(csc_results)} results]"
                
                # Create summaries for popup fields
                names_list = item.get("names", [])
                names_summary = f"[{len(names_list)} names] (double-click)" if names_list else ""
                trid_list = item.get("trid", [])
                trid_summary = f"[{len(trid_list)} entries] (double-click)" if trid_list else ""

                # Insert row with summary text
                row_values = (sha256, ttag, names_summary, size_val, rep, tlsh, ssd, trid_summary, sigma_count_str, csc_count_str)
                iid = tree_comm.insert("", "end", values=row_values)
                
                # Store full data for popups
                popup_data = {"dynamic_analysis": dynamic_analysis, "sha256": sha256}
                if names_list: popup_data["names"] = names_list
                if trid_list: popup_data["trid"] = trid_list
                item_data_map_comm[iid] = popup_data
                
        # --- Event handler for multiple popups ---
        def on_comm_file_double_click(event):
            item_id = tree_comm.identify_row(event.y)
            col_id = tree_comm.identify_column(event.x)
            
            if item_id in item_data_map_comm:
                item_data = item_data_map_comm[item_id]
                # Column #3 is "Names"
                if col_id == "#3" and "names" in item_data:
                    show_match_data_popup("Names", item_data["names"])
                # Column #8 is "TRID"
                elif col_id == "#8" and "trid" in item_data:
                    show_match_data_popup("TRID Details", item_data["trid"])
                # Fallback to the original dynamic analysis popup for other columns
                elif "dynamic_analysis" in item_data:
                    dynamic_data_for_popup = item_data.get("dynamic_analysis", {})
                    file_sha = item_data.get("sha256", "Selected File")
                    popup_title = f"Dynamic Analysis for: {file_sha}"
                    show_dynamic_analysis_popup(popup_title, dynamic_data_for_popup)

        tree_comm.bind("<Double-1>", on_comm_file_double_click)
        
        # --- UI element packing (Scrollbars) ---
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tree_comm.yview)
        tree_comm.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tree_comm.xview)
        tree_comm.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tree_comm.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tree_comm)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)


        def copy_all_data():
            lines = []
            # Define the full TRID string formatter locally
            def format_trid(trid_list):
                if isinstance(trid_list, list) and trid_list:
                    return "; ".join(f"{x.get('file_type','?')}({x.get('probability','?')})" for x in trid_list)
                return ""

            for child_id in tree_comm.get_children():
                vals = list(tree_comm.item(child_id, "values"))
                if child_id in item_data_map_comm:
                    full_data = item_data_map_comm[child_id]
                    # Replace "Names" summary (index 2) with full data
                    vals[2] = ", ".join(full_data.get("names", []))
                    # Replace "TRID" summary (index 7) with full data
                    vals[7] = format_trid(full_data.get("trid", []))
                
                line = "\t".join(str(v) for v in vals)
                lines.append(line)
                
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tree_comm
    
    def create_httpresp_treeview_dynamic(parent, http_data_dict):
        """
        Treeview with dynamic columns
        """
        tree_container = tk.Frame(parent, bg=BACKGROUND_COLOR)
        tree_container.pack(fill="both", expand=True, pady=5)

        if not http_data_dict:
            tk.Label(tree_container, text="No HTTP Response Data", bg=BACKGROUND_COLOR).pack(anchor="w", padx=5, pady=5)
            return

        columns = list(http_data_dict.keys())
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=3)
        for col in columns:
            tv.heading(col, text=col, anchor="w")
            tv.column(col, width=200, anchor="w", stretch=True, minwidth=100)

        row_values = [str(http_data_dict.get(col, "")) for col in columns]
        tv.insert("", "end", values=tuple(row_values))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=BACKGROUND_COLOR)
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", 
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        return tv


    def create_vertical_static_treeview(parent, data_dict):
        """
        Creates a vertically oriented Treeview with two columns: Field and Value.
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = ("Field", "Value")
        tree2 = ttk.Treeview(container, columns=columns, show="headings", height=12)
        tree2.heading("Field", text="Field", anchor="w")
        tree2.heading("Value", text="Value", anchor="w")
        tree2.column("Field", anchor="w", width=180, stretch=False, minwidth=120)
        tree2.column("Value", anchor="w", width=600, stretch=True, minwidth=200)

        # --- Popup logic ---
        item_data_map = {}
        def on_double_click(event):
            item_id = tree2.identify_row(event.y)
            if item_id in item_data_map:
                full_data = item_data_map[item_id]
                field_name = tree2.item(item_id, "values")[0]
                show_match_data_popup(f"Full Data for {field_name}", full_data)

        tree2.bind("<Double-1>", on_double_click)
        # ------------------

        def list_of_dicts_to_str(arr):
            if isinstance(arr, list):
                if not arr:
                    return ""
                if all(isinstance(x, dict) and "name" in x for x in arr):
                    return ", ".join(x["name"] for x in arr)
                else:
                    return ", ".join(str(x) for x in arr)
            return str(arr) if arr else ""

        file_type   = data_dict.get("File Type", "")
        magic       = data_dict.get("magic", "")
        size        = str(data_dict.get("size", ""))
        pe_meta     = data_dict.get("PE Metadata", {})
        linkers     = data_dict.get("linkers")
        compilers   = data_dict.get("compilers")
        tools       = data_dict.get("tools")
        packers     = data_dict.get("packers")
        installers  = data_dict.get("installers")

        comp_ts     = pe_meta.get("Compilation Timestamp", "")
        imphash     = pe_meta.get("imphash", "")
        machine_type= pe_meta.get("Machine Type", "")
        entry_point = pe_meta.get("Entry Point", "")
        rich_pe_hash= pe_meta.get("Rich PE Header Hash", "")

        linkers_str   = list_of_dicts_to_str(linkers)
        compilers_str = list_of_dicts_to_str(compilers)
        tools_str     = list_of_dicts_to_str(tools)

        if isinstance(packers, dict):
            packers_str = ", ".join(packers.keys()) if packers else ""
        else:
            packers_str = str(packers) if packers else ""
        installers_str = list_of_dicts_to_str(installers)

        # --- Standard Rows (excluding Trid and names) ---
        standard_rows = [
            ("File Type",              file_type),
            ("Magic",                  magic),
            ("Size",                   size),
            ("Compilation Timestamp",  comp_ts),
            ("imphash",               imphash),
            ("Machine Type",           machine_type),
            ("Entry Point",            entry_point),
            ("Rich PE Header Hash",    rich_pe_hash),
            ("Linkers",               linkers_str),
            ("Compilers",             compilers_str),
            ("Tools",                 tools_str),
            ("Packers",               packers_str),
            ("Installers",            installers_str),
        ]
        ssdeep_val   = data_dict.get("ssdeep", "")
        tlsh_val     = data_dict.get("tlsh", "")
        perm_val     = data_dict.get("permhash", "")
        auth_val     = data_dict.get("authentihash", "")
        telf_val     = data_dict.get("telfhash", "")

        if ssdeep_val:   standard_rows.append(("ssdeep", str(ssdeep_val)))
        if tlsh_val:     standard_rows.append(("tlsh", str(tlsh_val)))
        if perm_val:     standard_rows.append(("permhash", str(perm_val)))
        if auth_val:     standard_rows.append(("authentihash", str(auth_val)))
        if telf_val:     standard_rows.append(("telfhash", str(telf_val)))

        # Insert all standard rows
        for field_name, field_val in standard_rows:
            if field_val:
                tree2.insert("", "end", values=(field_name, field_val))

        # --- Special Rows with Popups ---
        # 1. Trid
        trid_list = data_dict.get("trid", [])
        if trid_list:
            summary_text = f"[{len(trid_list)} entries] (double-click to view)"
            iid = tree2.insert("", "end", values=("Trid", summary_text))
            item_data_map[iid] = trid_list

        # 2. Names
        names_list = data_dict.get("names", [])
        if names_list:
            summary_text = f"[{len(names_list)} names] (double-click to view)"
            iid = tree2.insert("", "end", values=("names", summary_text))
            item_data_map[iid] = names_list
        
        # --- .NET and ELF info ---
        dotnet_renames = {
            "entry_point_rva":       ".NET - Entry Point RVA",
            "metadata_header_rva":   ".NET - Metadata Header RVA",
            "assembly_name":         ".NET - Assembly Name",
            "resources_va":          ".NET - Resources VA",
            "assembly_flags":        ".NET - Assembly Flags",
            "entry_point_token":     ".NET - Entry Point Token",
            "tables_rows_map":       ".NET - Tables Rows Map",
        }
        dotnet_asm = data_dict.get("Dot Net Assembly", {})
        if isinstance(dotnet_asm, dict) and dotnet_asm:
            for subkey, subval in dotnet_asm.items():
                if not subval:
                    continue
                display_key = dotnet_renames.get(subkey, subkey)
                tree2.insert("", "end", values=(display_key, str(subval)))

        elf_renames = {
            "hdr_version":        "HDR Version",
            "type":               "Type",
            "obj_version":        "Object Version",
            "data":               "Data",
            "machine":            "Machine",
            "os_abi":             "OS ABI",
            "entrypoint":         "Entrypoint",
            "num_prog_headers":   "Number of Program Headers",
            "class":              "Class"
        }
        elf_header = data_dict.get("elf_info_header", {})
        if isinstance(elf_header, dict) and elf_header:
            for subkey, subval in elf_header.items():
                if subval is not None:
                    display_key = elf_renames.get(subkey, subkey)
                    tree2.insert("", "end", values=(display_key, str(subval)))
        
        # --- Final UI setup  ---
        vsb = ttk.Scrollbar(container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")

        tree2.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tree2)

        btn_container = tk.Frame(parent, bg=parent["bg"])
        btn_container.pack(fill="x", anchor="sw", pady=(3, 0))

        copy_btn = tk.Button(
            btn_container,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tree2.get_children():
                row_vals = tree2.item(child_id, "values")
                # Check if this row is one of our special popup rows
                if child_id in item_data_map:
                    # For popup rows, copy the full data, not the summary
                    full_data = item_data_map[child_id]
                    formatted_data = json.dumps(full_data, indent=2)
                    lines.append(f"{row_vals[0]}:\n{formatted_data}")
                else:
                    # For standard rows, copy as before
                    lines.append(f"{row_vals[0]}: {row_vals[1]}")
            
            joined_text = "\n\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tree2

    def create_multi_contacted_indicators_treeview(parent, items_list):
        """
        Displays Contacted Indicators grouped by scan_id.
        
        """
        tree_container = tk.Frame(parent, bg=parent.cget("bg"))
        tree_container.pack(fill="both", expand=True, pady=5)

        grouped = {}
        for item in items_list:
            scan_id = item.get("scan_id", "N/A")
            scan_date = item.get("scan_date", "")
            itype = item.get("indicator_type", "").upper()
            val = item.get("value", "")
            if scan_id not in grouped:
                grouped[scan_id] = {"scan_date": scan_date, "ips": [], "asns": [], "domains": []}
            if itype == "IP": grouped[scan_id]["ips"].append(val)
            elif itype == "ASN": grouped[scan_id]["asns"].append(val)
            elif itype == "DOMAIN": grouped[scan_id]["domains"].append(val)

        columns = ("Scan ID", "Scan Date", "IPs", "ASNs", "Domains")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        tv.heading("Scan ID", text="Scan ID", anchor="w"); tv.column("Scan ID", width=120, anchor="w", stretch=False, minwidth=120)
        tv.heading("Scan Date", text="Scan Date", anchor="w"); tv.column("Scan Date", width=150, anchor="w", stretch=False, minwidth=150)
        tv.heading("IPs", text="IP(s)", anchor="w"); tv.column("IPs", width=200, anchor="w", stretch=True, minwidth=200)
        tv.heading("ASNs", text="ASN(s)", anchor="w"); tv.column("ASNs", width=200, anchor="w", stretch=True, minwidth=200)
        tv.heading("Domains", text="Domain(s)", anchor="w"); tv.column("Domains", width=300, anchor="w", stretch=True, minwidth=300)

        item_data_map = {}
        def on_double_click(event):
            item_id = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)
            if item_id in item_data_map:
                # Column #3 is "IPs"
                if col_id == "#3":
                    full_data = item_data_map[item_id].get("ips", [])
                    if full_data: show_match_data_popup("Contacted IPs", full_data)
                # Column #5 is "Domains"
                elif col_id == "#5":
                    full_data = item_data_map[item_id].get("domains", [])
                    if full_data: show_match_data_popup("Contacted Domains", full_data)

        tv.bind("<Double-1>", on_double_click)

        if not grouped:
            tv.insert("", "end", values=("No Contacted Indicators", "", "", "", ""))
        else:
            for scan_id, data_dict in grouped.items():
                scan_date = data_dict["scan_date"]
                asns_joined = ", ".join(data_dict["asns"]) if data_dict["asns"] else ""
                
                ip_list = data_dict.get("ips", [])
                domain_list = data_dict.get("domains", [])
                ips_summary = f"[{len(ip_list)} IPs] (double-click)" if ip_list else ""
                domains_summary = f"[{len(domain_list)} domains] (double-click)" if domain_list else ""
                
                iid = tv.insert("", "end", values=(scan_id, scan_date, ips_summary, asns_joined, domains_summary))
                item_data_map[iid] = {"ips": ip_list, "domains": domain_list}

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = list(tv.item(child_id, "values"))
                if child_id in item_data_map:
                    full_data = item_data_map[child_id]
                    vals[2] = "; ".join(full_data.get("ips", []))      # Index 2 for IPs
                    vals[4] = "; ".join(full_data.get("domains", []))  # Index 4 for Domains
                line = "\t".join(str(v) for v in vals)
                lines.append(line)
            joined = "\n".join(lines); parent.clipboard_clear(); parent.clipboard_append(joined); parent.update()
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv
    def create_multi_webpage_analysis_treeview(parent, items_list):
        """
        Displays webpage analysis with a popup for HTTP Headers.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = (
            "Scan ID", "Scan Date", "IP", "ASN", "ASN Name", "PTR", "Status", "Title",
            "Subresource Size", "Server", "MIME Type", "Redirected?", "HTTP Headers", "Wappalyzer Apps"
        )
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        col_widths = [120, 200, 200, 120, 200, 200, 200, 200, 200, 200, 120, 120, 180, 180]
        for i, col in enumerate(columns):
            tv.heading(col, text=col, anchor="w"); tv.column(col, width=col_widths[i], anchor="w", stretch=False, minwidth=col_widths[i])

        item_data_map = {}
        def on_double_click(event):
            item_id = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)
            if item_id in item_data_map and col_id == "#13": # Column #13 is HTTP Headers
                full_data = item_data_map[item_id].get("http_server_headers", [])
                if full_data: show_match_data_popup("HTTP Server Headers", full_data)
        tv.bind("<Double-1>", on_double_click)

        if not items_list:
            tv.insert("", "end", values=("No Webpage Analysis",) + ("",)*13)
        else:
            for item in items_list:
                headers = item.get("http_server_headers", [])
                headers_summary = f"[{len(headers)} headers] (double-click)" if headers else ""
                wappa_str = "; ".join([f"{w.get('wappalyzer_app_name','?')} ({'/'.join(w.get('wappalyzer_categories',[]))})" for w in item.get("wappa_app", [])])
                
                rowvals = (
                    item.get("scan_id",""), item.get("scan_date",""), item.get("webpage_ip",""), item.get("webpage_asn",""),
                    item.get("webpage_asnname",""), item.get("webpage_ptr",""), item.get("webpage_status",""),
                    item.get("webpage_title",""), item.get("subresource_datasize",""), item.get("webpage_server",""),
                    item.get("webpage_mimeType",""), item.get("webpage_redirected",""), headers_summary, wappa_str
                )
                iid = tv.insert("", "end", values=rowvals)
                if headers:
                    item_data_map[iid] = {"http_server_headers": headers}
        
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = list(tv.item(child_id, "values"))
                if child_id in item_data_map:
                    vals[12] = "; ".join(item_data_map[child_id].get("http_server_headers", [])) # Index 12
                lines.append("\t".join(str(v) for v in vals))
            joined = "\n".join(lines); parent.clipboard_clear(); parent.clipboard_append(joined)
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv

    def create_multi_urlscan_verdict_treeview(parent, verdict_list):
        """
        Displays each urlscan verdict as a row.
        verdict_list is a list of dicts containing:
        "scan_id",
        "urlscan_score",
        "urlscan_categories" (list),
        "tasked_tags" (list)
        We'll display columns = ("Scan ID", "Score", "Categories", "Tags").
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = ("Scan ID", "Score", "Categories", "Tasked Tags")
        tv = ttk.Treeview(container, columns=columns, show="headings", height=8)

        tv.heading("Scan ID",       text="Scan ID", anchor="w")
        tv.heading("Score",         text="Score", anchor="w")
        tv.heading("Categories",    text="Categories", anchor="w")
        tv.heading("Tasked Tags",   text="Tasked Tags", anchor="w")

        tv.column("Scan ID",      width=120, anchor="w", stretch=True, minwidth=120)
        tv.column("Score",        width=60,  anchor="w", stretch=True, minwidth=60)
        tv.column("Categories",   width=220, anchor="w", stretch=True, minwidth=220)
        tv.column("Tasked Tags",  width=200, anchor="w", stretch=True, minwidth=200)

        if not verdict_list:
            tv.insert("", "end", values=("No urlscan verdict", "", "", ""))
        else:
            for item in verdict_list:
                scan_id = item.get("scan_id","")
                score   = item.get("urlscan_score","")
                cats    = item.get("urlscan_categories",[])
                cats_str = ", ".join(cats) if cats else ""
                tags    = item.get("tasked_tags",[])
                tags_str = ", ".join(tags) if tags else ""

                tv.insert("", "end", values=(scan_id, score, cats_str, tags_str))

        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = tv.item(child_id, "values")
                lines.append("\t".join(str(v) for v in vals))
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tv

    def create_multi_urlscan_httpresp_treeview(parent, items_list):
        """
        Displays urlscan HTTP response data. 
        """
        #Main container for the entire component
        main_container = tk.Frame(parent, bg=parent["bg"])
        main_container.pack(fill="both", expand=True, pady=5)
        
        # LabelFrame for the main treeview to give it a title 
        tree_lf = tk.LabelFrame(main_container, text="HTTP Response", font=("Segoe UI", 11, "bold"), bg=parent["bg"], fg="#000000", padx=10, pady=10)
        tree_lf.pack(fill="x", expand=True, padx=5, pady=5)
        
        tree_container = tk.Frame(tree_lf, bg=parent["bg"]) # Container for tree+scrollbars
        tree_container.pack(fill="both", expand=True)

        columns = ("Scan ID", "Scan Date", "TLS AgeDays", "TLS Issuer", "TLS ValidDays", "Link Domains")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)

        tv.heading("Scan ID", text="Scan ID", anchor="w"); tv.column("Scan ID", width=100, anchor="w", stretch=True, minwidth=100)
        tv.heading("Scan Date", text="Scan Date", anchor="w"); tv.column("Scan Date", width=160, anchor="w", stretch=True, minwidth=200)
        tv.heading("TLS AgeDays", text="TLS AgeDays", anchor="w"); tv.column("TLS AgeDays", width=120, anchor="w", stretch=True, minwidth=120)
        tv.heading("TLS Issuer", text="TLS Issuer", anchor="w"); tv.column("TLS Issuer", width=120, anchor="w", stretch=True, minwidth=120)
        tv.heading("TLS ValidDays", text="TLS ValidDays", anchor="w"); tv.column("TLS ValidDays", width=120, anchor="w", stretch=True, minwidth=120)
        tv.heading("Link Domains", text="Link Domains", anchor="w"); tv.column("Link Domains", width=250, anchor="w", stretch=True, minwidth=250)
        
        #
        item_data_map = {}
        def on_double_click(event):
            item_id = tv.identify_row(event.y)
            col_id = tv.identify_column(event.x)
            if item_id in item_data_map and col_id == "#6":
                full_data = item_data_map[item_id].get("linkDomains", [])
                if full_data: show_match_data_popup("Link Domains", full_data)
        tv.bind("<Double-1>", on_double_click)

        #
        for item in items_list:
            link_domains = item.get("linkDomains", [])
            link_dom_summary = f"[{len(link_domains)} domains] (double-click)" if link_domains else ""
            row_values = (item.get("scan_id", ""), item.get("scan_date", ""), item.get("webpage_tlsAgeDays", ""), item.get("webpage_tlsIssuer", ""), item.get("webpage_tlsValidDays", ""), link_dom_summary)
            iid = tv.insert("", "end", values=row_values)
            if link_domains: item_data_map[iid] = {"linkDomains": link_domains}

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="top", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(tree_lf, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = list(tv.item(child_id, "values"))
                if child_id in item_data_map:
                    vals[5] = "; ".join(item_data_map[child_id].get("linkDomains", []))
                lines.append("\t".join(str(v) for v in vals))
            joined = "\n".join(lines)
            parent.clipboard_clear(); parent.clipboard_append(joined)
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All"))
        copy_btn.config(command=copy_all_data)

        all_body_hashes = set(); all_requested_urls = set()
        for item in items_list:
            for bh in item.get("http_response_body_hash_list", []): all_body_hashes.add(bh)
            for url in item.get("requested_urls", []): all_requested_urls.add(url)
        
        if all_body_hashes:
            bh_frame = tk.LabelFrame(main_container, text="Body Hashes", font=("Segoe UI", 11, "bold"), bg=parent["bg"], fg="#000000", padx=10, pady=10)
            bh_frame.pack(fill="x", expand=True, padx=5, pady=5)
            create_bodyhash_treeview(bh_frame, sorted(all_body_hashes))
        
        if all_requested_urls:
            ru_frame = tk.LabelFrame(main_container, text="Requested URLs", font=("Segoe UI", 11, "bold"), bg=parent["bg"], fg="#000000", padx=10, pady=10)
            ru_frame.pack(fill="x", expand=True, padx=5, pady=5)
            create_requestedurls_treeview(ru_frame, sorted(all_requested_urls))

        return tv


    def create_multi_urlscan_http_certs_treeview(parent, cert_rows):
        """
        Displays each certificate as a single row grouped by scan_id.
        Columns = (Scan ID, subjectName, issuer, validFrom, validTo).
        """
        container = tk.Frame(parent, bg=BACKGROUND_COLOR)
        container.pack(fill="x", expand=True, pady=5)
        columns = ("Scan ID", "subjectName", "issuer", "validFrom", "validTo")

        tv = ttk.Treeview(container, columns=columns, show="headings", height=6)
        tv.heading("Scan ID", text="Scan ID", anchor="w")
        tv.heading("subjectName", text="Subject Name", anchor="w")
        tv.heading("issuer", text="Cert Issuer Org", anchor="w")
        tv.heading("validFrom", text="Not Before Cert Date", anchor="w")
        tv.heading("validTo", text="Not After Cert Date", anchor="w")

        tv.column("Scan ID",     width=160, anchor="w", stretch=False, minwidth = 160)
        tv.column("subjectName", width=220, anchor="w", stretch=False, minwidth = 220)
        tv.column("issuer",      width=220, anchor="w", stretch=True, minwidth = 220)
        tv.column("validFrom",   width=180, anchor="w", stretch=True, minwidth = 180)
        tv.column("validTo",     width=180, anchor="w", stretch=True, minwidth = 180)

        def epoch_to_string(e):
            """Helper to convert epoch (int/float) to a friendly date string."""
            try:
                return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            except:
                return str(e)

        for cert_dict in cert_rows:
            scan_id = cert_dict.get("scan_id", "")
            subject_name = cert_dict.get("subjectName", "")
            issuer_val = cert_dict.get("issuer", "")
            valid_from = cert_dict.get("validFrom", "")
            valid_to   = cert_dict.get("validTo", "")

            if isinstance(valid_from, (int, float)):
                valid_from = epoch_to_string(valid_from)
            if isinstance(valid_to, (int, float)):
                valid_to = epoch_to_string(valid_to)

            tv.insert("", "end", values=(
                scan_id,
                subject_name,
                issuer_val,
                valid_from,
                valid_to
            ))


        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tv.pack(side="top", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(container, bg=BACKGROUND_COLOR)
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = tv.item(child_id, "values")
                lines.append("\t".join(str(v) for v in vals))
            joined_text = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tv


    def create_multi_downloaded_treeview(parent, downloaded_items):
        """
        Creates a multi-column treeview showing each downloaded artifact as a row.
        Columns: scan_id, filename, size, mimeType, sha256, receivedBytes
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = (
            "Scan ID",
            "Scan Date",
            "Filename",
            "Filesize",
            "MIME Type",
            "SHA256",
            "Received Bytes"
        )
        tv = ttk.Treeview(container, columns=columns, show="headings", height=10)
        for col in columns:
            tv.heading(col, text=col, anchor="w")
        tv.column("Scan ID",       width=150, minwidth=150, anchor="w", stretch = False)
        tv.column("Scan Date",     width=200, minwidth=200, anchor="w", stretch = False)
        tv.column("Filename",      width=400, minwidth = 400, anchor="w", stretch = False)
        tv.column("Filesize",      width=130,  minwidth = 130, anchor="w", stretch = False)
        tv.column("MIME Type",     width=150, minwidth = 150, anchor="w", stretch = False)
        tv.column("SHA256",        width=400, minwidth = 400, anchor="w", stretch = False)
        tv.column("Received Bytes",width=160, minwidth = 160, anchor="w", stretch = False)

        # Insert one row per artifact
        if not downloaded_items:
            tv.insert("", "end", values=("No artifacts", "", "", "", "", ""))
        else:
            for art in downloaded_items:
                scan_id = art.get("scan_id","")
                scan_date = art.get("scan_date","")
                fname   = art.get("downloaded_filename","")
                fsize   = art.get("downloaded_filesize","")
                mime    = art.get("downloaded_file_mimeType","")
                sha2    = art.get("downloaded_sha256","")
                rbytes  = art.get("downloaded_file_receivedBytes","")

                tv.insert("", "end", values=(scan_id, scan_date, fname, fsize, mime, sha2, rbytes))

        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")

        tv.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                vals = tv.item(child_id, "values")
                lines.append("\t".join(str(v) for v in vals))
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv

    def build_single_column_treeview(parent, data_list, column_label="Value"):
        """
        Builds a single-column Treeview
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = (column_label,)
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading(column_label, text=column_label, anchor="w")
        tv.column(column_label, width=800, anchor="w", stretch=True)

        for item in data_list:
            tv.insert("", "end", values=(item,))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = [tv.item(child_id, "values")[0] for child_id in tv.get_children()]
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv

    def create_registrykeys_opened_treeview(parent, key_list):
        """Creates a single-column Treeview for opened registry keys"""
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("Opened Registry Key",)
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Opened Registry Key", text="Opened Registry Key", anchor="w")
        tv.column("Opened Registry Key", width=800, anchor="w", stretch=True)

        for regkey in key_list:
            tv.insert("", "end", values=(regkey,))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)

    def create_registrykeys_set_treeview(parent, data_list):
        """
        Creates a 2-column Treeview for registry keys set
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("Registry Key", "Value")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Registry Key", text="Registry Key", anchor="w")
        tv.heading("Value", text="Value", anchor="w")
        tv.column("Registry Key", width=700, anchor="w", stretch=True, minwidth=700)
        tv.column("Value", width=300, anchor="w", stretch=True, minwidth=300)

        for item in data_list:
            tv.insert("", "end", values=(item.get("key", ""), item.get("value", "")))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = [f"{tv.item(child_id, 'values')[0]} => {tv.item(child_id, 'values')[1]}" for child_id in tv.get_children()]
            joined = "\n".join(lines)
            parent.clipboard_clear(); parent.clipboard_append(joined)
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv


    def create_signature_matches_treeview(parent, signature_list):
        """
        Shows signature matches with popups
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("Description", "Match Data Summary")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Description", text="Description", anchor="w"); tv.column("Description", width=400, anchor="w", stretch=False, minwidth=300)
        tv.heading("Match Data Summary", text="Match Data (Double-click to view)", anchor="w"); tv.column("Match Data Summary", width=250, anchor="w", stretch=True, minwidth=200)

        item_data_map = {}
        if not signature_list:
            tv.insert("", "end", values=("No signature matches", ""))
        else:
            for index, sig in enumerate(signature_list):
                desc = sig.get("description", "")
                match_data_arr = sig.get("match_data", [])
                summary_text = f"[{len(match_data_arr)} matches]" if match_data_arr else "[No data]"
                iid = tv.insert("", "end", values=(desc, summary_text))
                item_data_map[iid] = match_data_arr

        def on_double_click(event):
            item_id = tv.identify_row(event.y)
            if item_id in item_data_map:
                description = tv.item(item_id, "values")[0]
                popup_title = f"Match Data for: {description[:50]}..." if description else "Match Data"
                show_match_data_popup(popup_title, item_data_map[item_id])
        
        tv.bind("<Double-1>", on_double_click)

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All Summaries", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all_summary_data():
            lines = [f"Description: {v[0]}\tMatch Summary: {v[1]}" for v in [tv.item(cid, "values") for cid in tv.get_children()]]
            joined = "\n".join(lines)
            parent.clipboard_clear(); parent.clipboard_append(joined); parent.update()
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All Summaries"))

        copy_btn.config(command=copy_all_summary_data)
        return tv

    def create_process_tree_treeview(parent, process_tree_data):
        """
        Creates a multi-column Treeview for the process tree, with a Copy All button.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = (
            "Process ID", "Process Name", "Child Process ID_1", "Child Process ID_1 Name",
            "Child Process ID_2", "Child Process ID_2 Name", "Files Written", "Files Deleted", "Files Opened"
        )
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=10)
        tv.heading("Process ID", text="Process ID", anchor="w"); tv.column("Process ID", width=80, anchor="w", stretch=False, minwidth=80)
        tv.heading("Process Name", text="Process Name", anchor="w"); tv.column("Process Name", width=420, anchor="w", stretch=False, minwidth=420)
        tv.heading("Child Process ID_1", text="Child Process ID_1", anchor="w"); tv.column("Child Process ID_1", width=120, anchor="w", stretch=False, minwidth=120)
        tv.heading("Child Process ID_1 Name", text="Child Process ID_1 Name", anchor="w"); tv.column("Child Process ID_1 Name", width=300, anchor="w", stretch=False, minwidth=300)
        tv.heading("Child Process ID_2", text="Child Process ID_2", anchor="w"); tv.column("Child Process ID_2", width=120, anchor="w", stretch=False, minwidth=120)
        tv.heading("Child Process ID_2 Name", text="Child Process ID_2 Name", anchor="w"); tv.column("Child Process ID_2 Name", width=300, anchor="w", stretch=False, minwidth=300)
        tv.heading("Files Written", text="Files Written", anchor="w"); tv.column("Files Written", width=180, anchor="w", stretch=False, minwidth=180)
        tv.heading("Files Deleted", text="Files Deleted", anchor="w"); tv.column("Files Deleted", width=180, anchor="w", stretch=False, minwidth=180)
        tv.heading("Files Opened", text="Files Opened", anchor="w"); tv.column("Files Opened", width=180, anchor="w", stretch=False, minwidth=180)
        
        def flatten_processes(node_list):
            for node in node_list:
                rowdata = {"process_id": node.get("process_id", ""),"process_name": node.get("name", ""),"files_written": node.get("files_written", []),"files_deleted": node.get("files_deleted", []),"files_opened": node.get("files_opened", []),"child_processes": node.get("children", [])}
                yield rowdata
                children = node.get("children", [])
                if children: yield from flatten_processes(children)
        for rowdata in flatten_processes(process_tree_data):
            pid = rowdata["process_id"]; pname = rowdata["process_name"]
            fw = ", ".join(rowdata["files_written"]) if rowdata["files_written"] else ""
            fd = ", ".join(rowdata["files_deleted"]) if rowdata["files_deleted"] else ""
            fo = ", ".join(rowdata["files_opened"]) if rowdata["files_opened"] else ""
            child_ids = []; child_names = []
            kids = rowdata["child_processes"]
            child_ids.append(kids[0].get("process_id","") if len(kids) >= 1 else "")
            child_names.append(kids[0].get("name","") if len(kids) >= 1 else "")
            child_ids.append(kids[1].get("process_id","") if len(kids) >= 2 else "")
            child_names.append(kids[1].get("name","") if len(kids) >= 2 else "")
            tv.insert("", "end", values=(pid, pname, child_ids[0], child_names[0], child_ids[1], child_names[1], fw, fd, fo))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)


    def create_files_dropped_treeview(parent, dropped_list):
        """
        Creates a 3-column Treeview for 'files_dropped'
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("Path", "SHA256", "File Type")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Path", text="Path", anchor="w"); tv.column("Path", width=600, anchor="w", stretch=True, minwidth=600)
        tv.heading("SHA256", text="SHA256", anchor="w"); tv.column("SHA256", width=400, anchor="w", stretch=True, minwidth=400)
        tv.heading("File Type", text="File Type", anchor="w"); tv.column("File Type", width=100, anchor="w", stretch=False, minwidth=100)

        for item in dropped_list:
            tv.insert("", "end", values=(item.get("path", ""), item.get("sha256", ""), item.get("type", "")))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = [f"Path={v[0]} | SHA256={v[1]} | Type={v[2]}" for v in [tv.item(cid, "values") for cid in tv.get_children()]]
            joined = "\n".join(lines)
            parent.clipboard_clear(); parent.clipboard_append(joined)
            copy_btn.config(text="Copied!"); parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tv

    def create_dns_lookups_treeview(parent, dns_lookups_list):
        """Creates a 2-column Treeview for DNS lookups."""
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("Hostname", "Resolved IP(s)")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        tv.heading("Hostname", text="Hostname", anchor="w"); tv.column("Hostname", width=300, anchor="w", stretch=True, minwidth=200)
        tv.heading("Resolved IP(s)", text="Resolved IP(s)", anchor="w"); tv.column("Resolved IP(s)", width=500, anchor="w", stretch=True, minwidth=200)
        
        rows_added = 0
        if not dns_lookups_list:
            tv.insert("", "end", values=("No DNS lookups found", ""))
        else:
            for item in dns_lookups_list:
                hostname = item.get("hostname", "")
                if hostname:
                    ips_str = ", ".join(item.get("resolved_ips", []))
                    tv.insert("", "end", values=(hostname, ips_str))
                    rows_added += 1
        if rows_added == 0: # If list was empty or had no hostnames
            if not tv.get_children(): 
                tv.insert("", "end", values=("No valid DNS lookups found", ""))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tv)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        return tv

    def create_behavior_summary_subtrees(parent, behaviour_summary):
        """
        Called from the 'Behavioral File Analysis' tab code. 
        This function sees which keys exist in `behaviour_summary`
        and builds subframes for each, but only if they contain data.
        """
        # Create the main container frame, but DO NOT pack it yet.
        # It will only be packed if at least one sub-section has data.
        bs_frame = tk.LabelFrame(
            parent,
            text="Behavior Summary",
            font=("Segoe UI", 12, "bold"),
            bg=parent["bg"],
            padx=10,
            pady=10
        )
        content_added = False

        # Helper function to keep the code clean 
        def create_section_if_data(key, title, creation_func, *args):
            """Checks for data, and only then creates the section's LabelFrame and Treeview."""
            nonlocal content_added
            # Get the data (e.g., a list of strings or dicts)
            data = behaviour_summary.get(key)
            
            if data:
                # show the main "Behavior Summary" frame by setting the flag to True
                content_added = True
                
                # Create the LabelFrame for this specific section (e.g., "Process Tree")
                # Note that its parent is `bs_frame`, not the top-level `parent`.
                lf = tk.LabelFrame(bs_frame, text=title, font=("Segoe UI", 11, "bold"), bg=parent["bg"])
                lf.pack(fill="both", expand=True, padx=5, pady=5)
                
                # Call the appropriate function to create the treeview inside the LabelFrame
                creation_func(lf, data, *args)

        # --- Use the helper function for every section ---
        
        create_section_if_data("command_executions", "Commands Executed", build_single_column_treeview, "Command")
        create_section_if_data("processes_tree", "Process Tree", create_process_tree_treeview)
        create_section_if_data("services_started", "Services Started", create_services_started_treeview)
        create_section_if_data("files_written", "Files Written", create_files_written_treeview)
        create_section_if_data("files_deleted", "Files Deleted", create_files_deleted_treeview)
        create_section_if_data("http_conversations", "HTTP Conversations", create_http_conversations_treeview)
        create_section_if_data("mutexes_created", "Mutexes Created", create_mutexes_created_treeview)
        create_section_if_data("calls_highlighted", "Calls Highlighted", create_calls_highlighted_treeview)
        create_section_if_data("registry_keys_set", "Registry Keys Set", create_registrykeys_set_treeview)
        create_section_if_data("registry_keys_opened", "Registry Keys Opened", create_registrykeys_opened_treeview)
        create_section_if_data("files_dropped", "Files Dropped", create_files_dropped_treeview)
        create_section_if_data("signature_matches", "Signature Matches", create_signature_matches_treeview)
        create_section_if_data("memory_pattern_urls", "Memory Pattern URLs", build_single_column_treeview, "URL")
        create_section_if_data("dns_lookups", "DNS Lookups", create_dns_lookups_treeview)
        create_section_if_data("ja3_digests", "JA3 Digests", create_ja3_treeview)
        create_section_if_data("ip_traffic", "IP Traffic", create_ip_traffic_treeview)

        # Finally, only if any section had data and set the flag to True,
        # pack the main "Behavior Summary" frame so it becomes visible.
        if content_added:
            bs_frame.pack(fill="both", expand=True, padx=5, pady=5)

    def create_bodyhash_treeview(parent, hash_list):
        """
        Builds a single-column Treeview listing each body hash on its own row.
        Attaches the universal right-click menu and a “Copy All” button.
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = ("Body Hash",)
        tv = ttk.Treeview(container, columns=columns, show="headings", height=6)
        tv.heading("Body Hash", text="Body Hash", anchor="w")
        tv.column("Body Hash", width=600, anchor="w", stretch=True)

        for h in hash_list:
            tv.insert("", "end", values=(h,))

        # Attach vertical scrollbar
        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        tv.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        # Add a “Copy All” button
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all():
            lines = []
            for child_id in tv.get_children():
                row_val = tv.item(child_id, "values")[0]
                lines.append(str(row_val))
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all)

        return tv


    def create_requestedurls_treeview(parent, url_list):
        """
        Builds a single-column Treeview listing each Requested URL on its own row.
        Attaches the universal right-click menu and a “Copy All” button.
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = ("Requested URL",)
        tv = ttk.Treeview(container, columns=columns, show="headings", height=6)
        tv.heading("Requested URL", text="Requested URL", anchor="w")
        tv.column("Requested URL", width=600, anchor="w", stretch=True)

        for url_str in url_list:
            tv.insert("", "end", values=(url_str,))

        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        tv.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        # Add “Copy All” button
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all():
            lines = []
            for child_id in tv.get_children():
                row_val = tv.item(child_id, "values")[0]
                lines.append(str(row_val))
            joined = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all)

        return tv

    def create_treeview_for_single_column_links(parent, link_list, column_header="Link"):
        """
        Builds a single-column Treeview that lists each string in 'link_list' 
        under the heading specified by 'column_header' (e.g. "Related URL" or "Outgoing Link").

        Also attaches:
        - Right-click context menu (with 'Copy Indicator', 'Search' cascade)
        - A "Copy All" button at the bottom
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        columns = (column_header,)
        tv = ttk.Treeview(container, columns=columns, show="headings", height=8)
        tv.heading(column_header, text=column_header, anchor="w")
        tv.column(column_header, width=600, anchor="w", stretch=True)

        # Insert each link/string as its own row
        for link_str in link_list:
            tv.insert("", "end", values=(link_str,))

        # Add scrollbars
        vsb = ttk.Scrollbar(container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        tv.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        # "Copy All" button
        btn_frame = tk.Frame(container, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0)) # Anchor to bottom-left of the container

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tv.get_children():
                row_vals = tv.item(child_id, "values")
                # row_vals is a 1-tuple, so row_vals[0] is the URL string
                lines.append(str(row_vals[0]))
            joined_text = "\n".join(lines)
            container.clipboard_clear()
            container.clipboard_append(joined_text)
            container.update()
            copy_btn.config(text="Copied!")
            container.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)

        return tv


    def create_treeview_for_dns_records(parent, records):
        # This container holds ONLY the tree and its scrollbars for proper layout
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("type", "ttl", "dns_name_value", "rname")
        tree2 = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        tree2.heading("type", text="Type", anchor="w")
        tree2.heading("ttl", text="TTL", anchor="w")
        tree2.heading("dns_name_value", text="dns name (value)", anchor="w")
        tree2.heading("rname", text="rname", anchor="w")
        tree2.column("type", width=130, anchor="w", stretch=True, minwidth=130)
        tree2.column("ttl", width=120, anchor="w", stretch=True, minwidth=120)
        tree2.column("dns_name_value", width=200, anchor="w", stretch=True, minwidth=200)
        tree2.column("rname", width=200, anchor="w", stretch=True, minwidth=200)

        if not records:
            tree2.insert("", "end", values=("No records", "", "", ""))
        else:
            for rec in records:
                t = rec.get("type", "NA")
                ttl = rec.get("ttl", "NA")
                val = rec.get("value", "NA")
                rname = rec.get("rname", "not applicable")
                tree2.insert("", "end", values=(t, ttl, val, rname))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tree2.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tree2)

        # Button frame is now a child of `parent`, packed below the tree_container
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tree2.get_children():
                row_vals = tree2.item(child_id, "values")
                lines.append("\t".join(str(v) for v in row_vals))
            joined_text = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tree2

    def create_validin_dns_history_treeview(parent, dns_history_data):
        """
        Creates a treeview for Validin DNS History data.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)
        
        columns = ("Record Type", "Value", "First Seen", "Last Seen")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=10)
        
        tv.heading("Record Type", text="Record Type", anchor="w")
        tv.heading("Value", text="Value", anchor="w")
        tv.heading("First Seen", text="First Seen", anchor="w")
        tv.heading("Last Seen", text="Last Seen", anchor="w")
        
        tv.column("Record Type", width=150, anchor="w", stretch=False, minwidth=100)
        tv.column("Value", width=300, anchor="w", stretch=True, minwidth=200)
        tv.column("First Seen", width=200, anchor="w", stretch=False, minwidth=150)
        tv.column("Last Seen", width=200, anchor="w", stretch=False, minwidth=150)
        
        # Helper to convert epoch to readable date
        def epoch_to_date(epoch_time):
            try:
                if epoch_time:
                    return datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                return ""
            except:
                return str(epoch_time)
        
        records = dns_history_data.get("records", [])
        if not records:
            tv.insert("", "end", values=("No DNS history found", "", "", ""))
        else:
            for record in records:
                tv.insert("", "end", values=(
                    record.get("record_type", ""),
                    record.get("value", ""),
                    epoch_to_date(record.get("first_seen", 0)),
                    epoch_to_date(record.get("last_seen", 0))
                ))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        
        tv.pack(side="left", fill="both", expand=True)
        
        # Bind right-click menu
        bind_treeview_right_click_menu(tv)
        
        # Copy All button
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        
        return tv


    def create_validin_dns_extra_treeview(parent, dns_extra_data):
        """
        Creates a treeview for Validin DNS Extra records.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)
        
        columns = ("Record Type", "Value", "First Seen", "Last Seen")
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=10)
        
        tv.heading("Record Type", text="Record Type", anchor="w")
        tv.heading("Value", text="Value", anchor="w")
        tv.heading("First Seen", text="First Seen", anchor="w")
        tv.heading("Last Seen", text="Last Seen", anchor="w")
        
        tv.column("Record Type", width=150, anchor="w", stretch=False, minwidth=100)
        tv.column("Value", width=400, anchor="w", stretch=True, minwidth=300)
        tv.column("First Seen", width=200, anchor="w", stretch=False, minwidth=150)
        tv.column("Last Seen", width=200, anchor="w", stretch=False, minwidth=150)
        
        def epoch_to_date(epoch_time):
            try:
                if epoch_time:
                    return datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                return ""
            except:
                return str(epoch_time)
        
        records = dns_extra_data.get("records", [])
        if not records:
            tv.insert("", "end", values=("No extra DNS records found", "", "", ""))
        else:
            for record in records:
                tv.insert("", "end", values=(
                    record.get("record_type", ""),
                    record.get("value", ""),
                    epoch_to_date(record.get("first_seen", 0)),
                    epoch_to_date(record.get("last_seen", 0))
                ))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        
        tv.pack(side="left", fill="both", expand=True)
        
        bind_treeview_right_click_menu(tv)
        
        # Copy All button
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv)
        )
        copy_btn.pack(side="left", padx=5)
        
        return tv



    def create_osint_textbox(parent, osint_data, title):
        """
        Creates a read-only textbox for OSINT data with a copy button.
        Handles both Domain and IP OSINT data formatting.
        """
        def epoch_to_date(epoch_time):
            """Helper to convert epoch to a readable date string."""
            if not epoch_time: return "N/A"
            try:
                # datetime and timezone are imported at the top of gui/app.py
                return datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (TypeError, ValueError, OSError):
                return str(epoch_time)

        observations = osint_data.get("observations", [])

        # Start building the formatted text
        indicator_value = osint_data.get('domain') or osint_data.get('ip', '')
        indicator_type_label = "Domain" if 'domain' in osint_data else "IP"
        formatted_text = f"{indicator_type_label}: {indicator_value}\n"
        formatted_text += f"Total Observations: {osint_data.get('total_observations', 0)}\n"
        formatted_text += "-" * 80 + "\n\n"

        if not observations:
            formatted_text += "No observations found."
        elif title in ["OSINT Context", "IP OSINT Context"]:
            # Format for Context data (both Domain and IP)
            for item in observations:
                formatted_text += f"Title: {item.get('title', 'N/A')}\n"
                formatted_text += f"Description: {item.get('description', 'N/A')}\n"
                formatted_text += f"Category: {item.get('category', 'N/A')}\n"
                formatted_text += f"Risk Category: {item.get('risk_cat', 'N/A')}\n"

                custom_data = item.get('custom', {})
                if custom_data:
                    aliases = ", ".join(custom_data.get('aliases', []))
                    references = custom_data.get('references', [])
                    formatted_text += f"Aliases: {aliases}\n" if aliases else ""
                    if references:
                        formatted_text += "References:\n"
                        for ref in references:
                            formatted_text += f"  - {ref}\n"

                ext_url = (custom_data.get('ext_url') if isinstance(custom_data, dict) 
                        else None) or item.get('maltrail')
                if ext_url:
                    formatted_text += f"Source URL: {ext_url}\n"

                formatted_text += "---\n"
        elif title in ["OSINT History", "IP OSINT History"]:
            # Format for History data (both Domain and IP)
            for item in observations:
                # Handle both formats - some have first_seen as epoch, others as ISO string
                first_seen = item.get('first_seen')
                last_seen = item.get('last_seen')
                
                # Check if it's an ISO string (contains 'T' or '-')
                if isinstance(first_seen, str) and ('T' in first_seen or '-' in first_seen):
                    first_seen_str = first_seen  # Already formatted
                else:
                    first_seen_str = epoch_to_date(first_seen)
                    
                if isinstance(last_seen, str) and ('T' in last_seen or '-' in last_seen):
                    last_seen_str = last_seen  # Already formatted
                else:
                    last_seen_str = epoch_to_date(last_seen)

                formatted_text += f"Value: {item.get('value', 'N/A')}\n"
                formatted_text += f"First Seen: {first_seen_str}\n"
                formatted_text += f"Last Seen: {last_seen_str}\n"

                tags = ", ".join(item.get('tags', []))
                formatted_text += f"Tags: {tags}\n" if tags else ""

                url = item.get('url')
                formatted_text += f"Source: {url}\n" if url else ""

                formatted_text += "---\n"
        else:
            # Fallback to JSON dump if title is unexpected
            formatted_text += json.dumps(observations, indent=2)

        # Create the textbox with scroll
        create_textbox_with_scroll(
            parent,
            formatted_text.strip(),
            bg_color="#FFFFFF",
            font_style=("Consolas", 10),
            width=80,
            height=15,
            include_copy_button=True
        )
    def create_vt_relationship_treeview(parent, data_list, column_header="Value"):
        """
        Builds a single-column Treeview for VT relationships.
        """
        # Container for the treeview and its scrollbars
        tree_container = tk.Frame(parent, bg=parent.cget("bg"))
        tree_container.pack(fill="both", expand=True)

        columns = (column_header,)
        tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=6)
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        tv.heading(column_header, text=column_header, anchor="w")
        tv.column(column_header, width=600, anchor="w", stretch=True)

        # Pack widgets inside tree_container
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tv.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tv)

        unique_data = sorted(list(set(data_list)))
        if not unique_data:
            tv.insert("", "end", values=(f"No {column_header.lower()} found.",))
        else:
            for item_str in unique_data:
                tv.insert("", "end", values=(item_str,))

        # Button frame is a child of `parent` (the LabelFrame)
        btn_frame = tk.Frame(parent, bg=parent.cget("bg"))
        btn_frame.pack(side="bottom", fill="x", anchor="sw", pady=(3,0))
        copy_btn = tk.Button(btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tv))
        copy_btn.pack(side="left", padx=5)

        return tv

    # sandbox verdicts
    def original_create_treeview_for_sandbox_verdicts(parent, verdicts_list):
        """
        Creates a multi-column Treeview for sandbox verdicts, with a Copy All button.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)
        
        columns = ("sandbox_name", "category", "malware_names", "confidence")
        tree2 = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        tree2.heading("sandbox_name", text="Sandbox Name", anchor="w"); tree2.column("sandbox_name", width=150, anchor="w", stretch=True, minwidth=150)
        tree2.heading("category", text="Category", anchor="w"); tree2.column("category", width=160, anchor="w", stretch=True, minwidth=160)
        tree2.heading("malware_names", text="Malware Names", anchor="w"); tree2.column("malware_names", width=250, anchor="w", stretch=True, minwidth=250)
        tree2.heading("confidence", text="Confidence", anchor="w"); tree2.column("confidence", width=150, anchor="w", stretch=True, minwidth=150)

        if not verdicts_list:
            tree2.insert("", "end", values=("No sandbox verdicts", "", "", ""))
        else:
            for item in verdicts_list:
                mal_str = ", ".join(item.get("malware_names", [])) or "not applicable"
                tree2.insert("", "end", values=(item.get("sandbox_name", ""), item.get("category", ""), mal_str, str(item.get("confidence", ""))))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tree2.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", 
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tree2)
        )
        copy_btn.pack(side="left", padx=5)
        
        return tree2

    def create_treeview_for_sandbox_verdicts(parent, verdicts_list):
        tv = original_create_treeview_for_sandbox_verdicts(parent, verdicts_list)
        bind_treeview_right_click_menu(tv)
        # Add a "Copy All" button is already in that code
        return tv


    def create_treeview_for_sigma(parent, sigma_list):
        """
        Creates a multi-column Treeview for Sigma results with a Copy All button.
        """
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = (
            "Rule Title", "Level", "Rule ID", "Rule Description", "OriginalFileName", "CommandLine", 
            "ParentCommandLine", "Image", "ParentImage", "QueryResults", "QueryName", "EventID", 
            "query", "DestinationHostname", "DestinationIp", "DestinationPort", "ScriptBlockText", 
            "Path", "TargetFilename", "Details", "EventType", "TargetObject"
        )
        tree2 = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        for col in columns:
            tree2.heading(col, text=col, anchor="w")
            tree2.column(col, width=200, anchor="w", stretch=False, minwidth=200)

        if not sigma_list:
            tree2.insert("", "end", values=("No Sigma results",))
        else:
            for item in sigma_list:
                rule_title = item.get("rule_title") or ""; rule_level = item.get("rule_level") or ""
                rule_id = item.get("rule_id") or ""; rule_description = item.get("rule_description") or ""
                contexts = item.get("match_context", [])
                if not contexts:
                    row_vals = [rule_title, rule_level, rule_id, rule_description] + ([""] * 18)
                    tree2.insert("", "end", values=tuple(row_vals))
                else:
                    for ctx in contexts:
                        row_vals = [
                            rule_title, rule_level, rule_id, rule_description, ctx.get("OriginalFileName",""),
                            ctx.get("CommandLine",""), ctx.get("ParentCommandLine",""), ctx.get("Image",""),
                            ctx.get("ParentImage",""), ctx.get("QueryResults",""), ctx.get("QueryName",""),
                            ctx.get("EventID",""), ctx.get("query",""), ctx.get("DestinationHostname",""),
                            ctx.get("DestinationIp",""), ctx.get("DestinationPort",""), ctx.get("ScriptBlockText",""),
                            ctx.get("Path",""), ctx.get("TargetFilename",""), ctx.get("Details",""),
                            ctx.get("EventType",""), ctx.get("TargetObject",""),
                        ]
                        tree2.insert("", "end", values=tuple(row_vals))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set); hsb.pack(side="bottom", fill="x")
        tree2.pack(side="left", fill="both", expand=True)
        bind_treeview_right_click_menu(tree2)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white",
            font=("Segoe UI", 10, "bold"), command=lambda: copy_all_treeview(tree2)
        )
        copy_btn.pack(side="left", padx=5)
        return tree2

    def original_create_treeview_for_crowdsourced_ids(parent, csc_list):
        """
        We'll create columns including src_ip, src_port, dest_ip, etc.
        We'll insert one row per "alert_context" item, or a single row if there's none.
        """
        container = tk.Frame(parent, bg=parent["bg"])
        container.pack(fill="x", expand=True, pady=5)

        # Our expanded columns:
        columns = (
            "rule_category", "alert_severity", "rule_msg",
            "rule_id", "rule_source", "rule_url", "rule_references",
            "src_ip", "src_port", "dest_ip", "dest_port",
            "ja3", "ja3s", "hostname", "url"
        )

        tree2 = ttk.Treeview(container, columns=columns, show="headings", height=8)
        for col in columns:
            tree2.heading(col, text=col, anchor="w")
            tree2.column(col, width=200, anchor="w", stretch=False, minwidth=200)

        if not csc_list:
            # Insert a single row that says "No crowdsourced IDs"
            tree2.insert("", "end", values=("No crowdsourced IDs",))
        else:
            for item in csc_list:
                rule_category    = item.get("rule_category","")
                alert_severity  = item.get("alert_severity","")
                rule_msg        = item.get("rule_msg","")
                rule_id         = item.get("rule_id","")
                rule_source     = item.get("rule_source","")
                rule_url        = item.get("rule_url","")
                rrefs = item.get("rule_references") or []
                rule_refs       = ", ".join(rrefs) if rrefs else ""

                alert_context = item.get("alert_context", [])
                if not alert_context:
                    # Insert one row with "" in the context columns
                    row_vals = [
                        rule_category, alert_severity, rule_msg,
                        rule_id, rule_source, rule_url, rule_refs,
                        "","","","","","","",""
                    ]
                    tree2.insert("", "end", values=tuple(row_vals))
                else:
                    # We have multiple contexts
                    for ctx in alert_context:
                        row_vals = [
                            rule_category,
                            alert_severity,
                            rule_msg,
                            rule_id,
                            rule_source,
                            rule_url,
                            rule_refs,
                            ctx.get("src_ip",""),
                            ctx.get("src_port",""),
                            ctx.get("dest_ip",""),
                            ctx.get("dest_port",""),
                            ctx.get("ja3",""),
                            ctx.get("ja3s",""),
                            ctx.get("hostname",""),
                            ctx.get("url",""),
                        ]
                        tree2.insert("", "end", values=tuple(row_vals))

        vsb = ttk.Scrollbar(container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")

        tree2.pack(side="left", fill="both", expand=True)

        bind_treeview_right_click_menu(tree2)

        # "Copy All" button
        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(fill="x", expand=True, pady=3)

        copy_btn = tk.Button(
            btn_frame,
            text="Copy All",
            bg="#9370DB",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for child_id in tree2.get_children():
                vals = tree2.item(child_id, "values")
                lines.append("\t".join(str(v) for v in vals))
            joined_text = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tree2

    def original_create_treeview_for_categories(parent, categories_dict):
        # This container holds ONLY the tree and its scrollbars
        tree_container = tk.Frame(parent, bg=parent["bg"])
        tree_container.pack(fill="both", expand=True, pady=5)

        columns = ("provider", "category")
        tree2 = ttk.Treeview(tree_container, columns=columns, show="headings", height=8)
        tree2.heading("provider", text="Provider", anchor="w")
        tree2.heading("category", text="Category", anchor="w")
        tree2.column("provider", width=180, anchor="w")
        tree2.column("category", width=600, anchor="w")

        if not categories_dict:
            tree2.insert("", "end", values=("No categories", ""))
        else:
            for provider, category_val in categories_dict.items():
                tree2.insert("", "end", values=(provider, category_val))

        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tree2.yview)
        tree2.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tree2.xview)
        tree2.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        tree2.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(parent, bg=parent["bg"])
        btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))

        copy_btn = tk.Button(
            btn_frame, text="Copy All", bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold")
        )
        copy_btn.pack(side="left", padx=5)

        def copy_all_data():
            lines = []
            for provider, category_val in categories_dict.items():
                lines.append(f"{provider}: {category_val}")
            joined_text = "\n".join(lines)
            parent.clipboard_clear()
            parent.clipboard_append(joined_text)
            parent.update()
            copy_btn.config(text="Copied!")
            parent.after(2000, lambda: copy_btn.config(text="Copy All"))

        copy_btn.config(command=copy_all_data)
        return tree2
    
    def create_treeview_for_categories(parent, categories_dict):
        tv = original_create_treeview_for_categories(parent, categories_dict)
        bind_treeview_right_click_menu(tv)
        return tv

    def create_treeview_for_crowdsourced_ids(parent, csc_list):
        tv = original_create_treeview_for_crowdsourced_ids(parent, csc_list)
        bind_treeview_right_click_menu(tv)
        return tv

    def group_validin_headers(grouped_dns_data):
            """
            Given the pre-processed Validin DNS results (grouped_dns_data, a dict where keys are header names
            and values are JOINED STRINGS), group them into the following 4 categories:
            - Certificate: if header starts with "CERT_DOMAIN" or "HOST-CERT"
            - Anchor: if header starts with "ANCHORS_LINKS"
            - Location: if header starts with "HOST-LOCATION" or "LOCATION_DOMAIN"
            - Host: everything else that starts with "HOST-"

            Returns a dict with keys "Certificate", "Anchor", "Location", "Host".
            Headers identified as lists (like HOST-CERT_DOMAIN) are not processed.
            """
            groups = {"Certificate": {}, "Anchor": {}, "Location": {}, "Host": {}}
            # Iterate through the pre-joined key-value pairs
            for header, joined_value in grouped_dns_data.items():
                # We already filtered empty values in the query function,
                # but double-check just in case.
                if not joined_value:
                    continue

                # Grouping logic based on header prefix
                if header.startswith("CERT_DOMAIN") or header.startswith("HOST-CERT"):
                    groups["Certificate"][header] = joined_value
                elif header.startswith("ANCHORS_LINKS"):
                    # Only add if the value is not empty
                    if joined_value: groups["Anchor"][header] = joined_value
                elif header.startswith("HOST-LOCATION") or header.startswith("LOCATION_DOMAIN"):
                    # Only add if the value is not empty
                    if joined_value: groups["Location"][header] = joined_value
                elif header.startswith("HOST-"):
                    # Only add if the value is not empty
                    if joined_value: groups["Host"][header] = joined_value
                else:
                    # Fallback for any other non-empty headers
                    if joined_value: groups["Host"][header] = joined_value # Default to Host

            # Filter out empty groups before returning
            groups = {k: v for k, v in groups.items() if v}
            return groups


    def copy_all_treeview(tree):
        """
        Copies all rows from a given Treeview to the clipboard.
        """
        lines = []
        for child in tree.get_children():
            vals = tree.item(child, "values")
            lines.append("\t".join(str(x) for x in vals))
        text = "\n".join(lines)
        tree.clipboard_clear()
        tree.clipboard_append(text)


    def create_validin_treeview(parent, kv_map, group_name):
        """
        Given a dictionary (kv_map) of header-(joined)value pairs for a specific Validin group,
        build a Treeview inside the given parent frame that shows these keys and values.
        Skips rows where the value is empty.

        Special handling for CERT_DOMAIN-HOST to split domains into individual rows.
        """
        # Create the Treeview with two columns.
        tree = ttk.Treeview(parent, columns=("Header", "Value"), show="headings")
        tree.heading("Header", text="Header", anchor="w")
        tree.heading("Value", text="Value", anchor="w")
        tree.column("Header", width=250, anchor="w", stretch=False, minwidth=150) 
        tree.column("Value", width=600, anchor="w", stretch=True, minwidth=300)  

        rows_added = 0
        # Insert each key/value as a row, ONLY if value is not empty.
        for header, value in kv_map.items():
            value_str = str(value).strip()
            if value_str: # Check if the value is non-empty
                cleaned_value = value_str.lstrip(', ') # Strip leading comma/space just in case
                
                # Special handling for CERT_DOMAIN-HOST to split domains
                if header == "CERT_DOMAIN-HOST" and "," in cleaned_value:
                    # Split the domains and create individual rows
                    domains = [domain.strip() for domain in cleaned_value.split(",") if domain.strip()]
                    for domain in domains:
                        tree.insert("", "end", values=(header, domain))
                        rows_added += 1
                else:
                    # Normal single-row insertion
                    tree.insert("", "end", values=(header, cleaned_value))
                    rows_added += 1

        if rows_added == 0:
            return # Don't pack the empty tree or scrollbars

        # Set dynamic height based on rows added, up to a max (e.g., 15 for cert domains)
        tree_height = min(rows_added, 15)
        tree.configure(height=tree_height)

        # Attach both vertical and horizontal scrollbars.
        vbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hbar = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        vbar.pack(side="right", fill="y")
        hbar.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)

        # Bind the right-click context menu
        bind_treeview_right_click_menu(tree)

        btn = tk.Button(parent, text="Copy All", command=lambda: copy_all_treeview(tree),
                        bg="#9370DB", fg="white", font=("Segoe UI", 10, "bold"))
        btn.pack(pady=5, side="bottom")

    def create_dynamic_treeview(parent_frame, title, columns_config, data_list):
            """
            Creates a generic, multi-column Treeview inside a LabelFrame.
            Handles data population, scrollbars, right-click menu, and a 'Copy All' button.
            """
            if not data_list:
                return # Don't create anything if there's no data

            # Main container for this section
            lf = tk.LabelFrame(parent_frame, text=title, font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
            lf.pack(fill="x", expand=True, padx=5, pady=5)
            
            tree_container = tk.Frame(lf, bg=BACKGROUND_COLOR)
            tree_container.pack(fill="both", expand=True)

            column_keys = list(columns_config.keys())
            tv = ttk.Treeview(tree_container, columns=column_keys, show="headings", height=8)

            for key, config in columns_config.items():
                tv.heading(key, text=config.get("text", key), anchor="w")
                tv.column(key, width=config.get("width", 150), anchor="w", stretch=config.get("stretch", False), minwidth=config.get("minwidth", 80))

            # Helper to convert epoch timestamps to a readable string
            def epoch_to_date_str(epoch):
                if not epoch: return ""
                try: return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except: return str(epoch)

            # Populate the treeview
            for item in data_list:
                row_values = []
                for key in column_keys:
                    value = item.get(key, "")
                    # Automatically convert timestamps for known date fields
                    if key in ["date", "first_seen", "last_seen", "record_type"] and isinstance(value, (int, float)):
                        row_values.append(epoch_to_date_str(value))
                    else:
                        row_values.append(str(value))
                tv.insert("", "end", values=tuple(row_values))

            # Add scrollbars and bind right-click menu
            vsb = ttk.Scrollbar(tree_container, orient="vertical", command=tv.yview)
            tv.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            
            hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=tv.xview)
            tv.configure(xscrollcommand=hsb.set)
            hsb.pack(side="bottom", fill="x")

            tv.pack(side="left", fill="both", expand=True)
            bind_treeview_right_click_menu(tv)

            # Add "Copy All" button
            btn_frame = tk.Frame(lf, bg=BACKGROUND_COLOR)
            btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
            copy_btn = tk.Button(btn_frame, text="Copy All", bg=BUTTON_COLOR, fg="white", font=FONT_BUTTON, command=lambda: copy_all_treeview(tv))
            copy_btn.pack(side="left", padx=5)
    def show_details(event):
        """
        Called whenever the user selects an item in the main tree. Clears the 
        notebook tabs, then rebuilds the detail views for the selected IOC.
        """
        def ensure_not_empty(frame):
            """
            If 'frame' has no children, place a label that says
            'No data returned for the IOC.'
            """
            # Check if the frame itself has children. If it has LabelFrames that are empty,
            
            # Clear previous "No data" message if any
            for widget in frame.winfo_children():
                if isinstance(widget, tk.Label) and widget.cget("text") == "No data returned for the IOC.":
                    widget.destroy()

            if not frame.winfo_children(): # If frame is truly empty after clearing
                tk.Label(
                    frame,
                    text="No data returned for the IOC.",
                    font=FONT_LABEL,
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    anchor="center",
                    justify="center"
                ).pack(padx=10, pady=10,fill="both",expand=True)

        for w in ioc_fields_inner.winfo_children():
            w.destroy()
        for w in static_analysis_inner.winfo_children():
            w.destroy()
        for w in relationships_inner.winfo_children():
            w.destroy()
        for w in dynamic_analysis_inner.winfo_children():
            w.destroy()
        for w in certificates_inner.winfo_children():
            w.destroy()
        for w in dns_inner.winfo_children():
            w.destroy()
        for w in web_analysis_inner.winfo_children():
            w.destroy()

        sel = tree.selection()
        if not sel:
            return
        ioc_val = tree.item(sel[0], "values")[0]
        ioc_data = response_cache.get(ioc_val)
        
# New check (around line 1929)
        if not ioc_data or not ioc_data.get("data"):
            # If no data, display message only in the first tab ('Indicator Details')
            tk.Label(
                ioc_fields_inner,
                text="No results were returned for this IOC.",
                font=FONT_LABEL, bg=BACKGROUND_COLOR, fg=TEXT_COLOR
            ).pack(pady=20)
            # Call ensure_not_empty for other tabs to show 'No data' there too
            ensure_not_empty(static_analysis_inner)
            ensure_not_empty(relationships_inner)
            ensure_not_empty(dynamic_analysis_inner)
            ensure_not_empty(certificates_inner)
            ensure_not_empty(dns_inner)
            ensure_not_empty(web_analysis_inner)
            status_bar.config(text=f"No cached data found for {ioc_val}")
            return # Stop processing if no data

        # Continue only if data exists
        data = ioc_data["data"]
        ioc_type_ = ioc_data["type"]
        if ioc_type_ == "file_hash":
            # For file hashes, these tabs will never have relevant data for the primary IOC
            ensure_not_empty(dns_inner)
            ensure_not_empty(web_analysis_inner)
        dynamic_data = data.get("dynamic_analysis", {})
        st_sections = data.get("securitytrails_sections", {})
        vt_rels = data.get("relationships", {}) # Get VT relationships data

        # ------------------------------
        # 1) INDICATOR DETAILS tab
        #    => "Vendors Marked Malicious", "Reputation", "urlscan Verdict", "Last VT Analysis Date"
        # ------------------------------
        # (a) Vendors Marked Malicious
        has_indicator_details_data = False
        vt_id_content_added = False # <-- ADD Flag

# === 1) A sub-Labelframe for VirusTotal-based fields:
        vt_id_frame = tk.LabelFrame(
            ioc_fields_inner,
            text="VirusTotal",
            font=("Segoe UI", 12, "bold"),
            bg=BACKGROUND_COLOR,
            fg=TEXT_COLOR,
            padx=10,
            pady=10
        )
        # vt_id_frame.pack(fill="x", padx=5, pady=5) # DON'T pack immediately


        # If "vendors_marked_malicious" is present:
        if "vendors_marked_malicious" in data:
            create_subfield_box(vt_id_frame, "Vendors Marked Malicious",
                                data["vendors_marked_malicious"], BACKGROUND_COLOR)
            vt_id_content_added = True # <-- SET Flag

        # If "reputation" is present:
        if "reputation" in data:
            create_subfield_box(vt_id_frame, "Reputation", data["reputation"], BACKGROUND_COLOR)
            vt_id_content_added = True # <-- SET Flag

        # If "last_analysis_date" => that goes under "Last VT Analysis Date"
        if "last_analysis_date" in data:
            create_subfield_box(vt_id_frame, "Last VT Analysis Date",
                                data["last_analysis_date"], BACKGROUND_COLOR)
            vt_id_content_added = True # <-- SET Flag

        # VirusTotal comments
        if "vt_comments" in data:
            c_frame = tk.LabelFrame(
                vt_id_frame,
                text="VirusTotal Comments",
                font=("Segoe UI", 11, "bold"),
                bg=BACKGROUND_COLOR, fg=TEXT_COLOR,
                padx=10, pady=5
            )
            c_frame.pack(fill="x", expand=True, padx=5, pady=5) # Pack sub-frame

            create_textbox_with_scroll(
                c_frame,
                data["vt_comments"],
                bg_color="#FFFFFF",
                font_style=FONT_TREE,
                width=70,
                height=10,
                include_copy_button=True
            )
            vt_id_content_added = True # <-- SET Flag

        if vt_id_content_added:
            vt_id_frame.pack(fill="x", padx=5, pady=5)
            has_indicator_details_data = True # Content was added
        elif vt_id_frame.winfo_exists(): # If created but nothing added
            vt_id_frame.destroy()
        # --- End Conditional Packing ---

        st_id_content_added = False
        # === 2) A sub-Labelframe for SecurityTrails verdict (Conditional Packing added)
        if "urlscan Verdict" in st_sections:
            st_id_frame = tk.LabelFrame(
                ioc_fields_inner,
                text="URLScan Verdict",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            # st_id_frame.pack(fill="x", padx=5, pady=5) # DON'T pack immediately

            uv = st_sections["urlscan Verdict"]
            verdict_items = uv.get("verdict_items", [])
            if verdict_items: # Only pack and populate if there's data
                st_id_frame.pack(fill="x", padx=5, pady=5)
                create_multi_urlscan_verdict_treeview(st_id_frame, verdict_items)
                st_id_content_added = True
                has_indicator_details_data = True # Content was added
            elif st_id_frame.winfo_exists():
                st_id_frame.destroy()

        if not has_indicator_details_data: # Check the overall flag for this tab
            ensure_not_empty(ioc_fields_inner)

        validin_id_content_added = False
        validin_id_frame = None

        if "validin_osint_context" in data or "validin_osint_history" in data:
            validin_id_frame = tk.LabelFrame(
                ioc_fields_inner,
                text="Validin",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            
            # OSINT Context
            if "validin_osint_context" in data:
                osint_ctx_frame = tk.LabelFrame(
                    validin_id_frame,
                    text="OSINT Context",
                    font=("Segoe UI", 11, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=5
                )
                osint_ctx_frame.pack(fill="x", padx=5, pady=5)
                create_osint_textbox(osint_ctx_frame, data["validin_osint_context"], "OSINT Context")
                validin_id_content_added = True
            
            # OSINT History
            if "validin_osint_history" in data:
                osint_hist_frame = tk.LabelFrame(
                    validin_id_frame,
                    text="OSINT History",
                    font=("Segoe UI", 11, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=5
                )
                osint_hist_frame.pack(fill="x", padx=5, pady=5)
                create_osint_textbox(osint_hist_frame, data["validin_osint_history"], "OSINT History")
                validin_id_content_added = True
            
            if validin_id_content_added:
                validin_id_frame.pack(fill="x", padx=5, pady=5)
                has_indicator_details_data = True

        # Section for Validin IP OSINT data
        if "validin_ip_osint_context" in data or "validin_ip_osint_history" in data:
            validin_ip_frame = tk.LabelFrame(
                ioc_fields_inner,
                text="Validin",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            validin_ip_frame_content_added = False

            # Validin IP OSINT Context
            ip_context_data = data.get('validin_ip_osint_context')
            if ip_context_data and ip_context_data.get("observations"):
                ip_context_frame = tk.LabelFrame(validin_ip_frame, text="IP OSINT Context", font=("Segoe UI", 11, "bold"),bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                ip_context_frame.pack(pady=5, padx=5, fill='x', expand=True)
                create_osint_textbox(ip_context_frame, ip_context_data, "IP OSINT Context")
                validin_ip_frame_content_added = True

            # Validin IP OSINT History
            ip_history_data = data.get('validin_ip_osint_history')
            if ip_history_data and ip_history_data.get("observations"):
                ip_history_frame = tk.LabelFrame(validin_ip_frame, text="IP OSINT History", font=("Segoe UI", 11, "bold"),bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                ip_history_frame.pack(pady=5, padx=5, fill='x', expand=True)
                create_osint_textbox(ip_history_frame, ip_history_data, "IP OSINT History")
                validin_ip_frame_content_added = True
            
            if validin_ip_frame_content_added:
                validin_ip_frame.pack(fill="x", padx=5, pady=5)
                has_indicator_details_data = True
        # ------------------------------
        # 2) CERTIFICATES tab
        #    => "last_http_response_headers" from VirusTotal if domain/IP/URL
        #    => plus "urlscan HTTP Certs" from st_sections => "urlscan HTTP Response"
        # ------------------------------
        has_cert_data = False
        vt_cert_data = None
        # We'll only show if ioc_type_ is domain or ip_address, or if the data has "last_http_response_headers"
        if ioc_type_ in ("domain","ip_address", "url") and "last_http_response_headers" in data:
            vt_cert_data = data["last_http_response_headers"]
        if vt_cert_data and isinstance(vt_cert_data, dict):
            cert_lf = tk.LabelFrame(
                certificates_inner,
                text="VirusTotal",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            cert_lf.pack(fill="x", padx=5, pady=5)
            create_certificate_details_tree(cert_lf, vt_cert_data)
            has_cert_data = True
        # The actual certs live in st_sections["urlscan HTTP Response"]["http_items"][...]["http_response_certificates"]
        all_urlscan_certs = []
        if "urlscan HTTP Response" in st_sections:
            http_items_list = st_sections["urlscan HTTP Response"].get("http_items", [])
            for hi in http_items_list:
                scan_id = hi.get("scan_id","")
                certlist = hi.get("http_response_certificates") or [] 
                for cdict in certlist:
                    if cdict:
                        ccopy = dict(cdict)
                        ccopy["scan_id"] = scan_id
                        all_urlscan_certs.append(ccopy)

        if all_urlscan_certs:
            cert_lf2 = tk.LabelFrame(
                certificates_inner,
                text="URLScan",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            cert_lf2.pack(fill="x", padx=5, pady=5)
            create_multi_urlscan_http_certs_treeview(cert_lf2, all_urlscan_certs)
            has_cert_data = True
        
        if not has_cert_data:
            tk.Label(
                certificates_inner,
                text="No data returned for the IOC.",
                font=FONT_LABEL,
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                anchor="center",
                justify="center"
            ).pack(expand=True, fill="both", padx=10, pady=10)


# 3) DNS Analysis tab
        # ------------------------------
        has_dns_data = False # Overall flag for this tab

        # Only populate this tab for domain or URL IOCs
        if ioc_type_ in ("domain", "url"):
            # Create the main container for VirusTotal data for this tab
            dns_vt_frame = tk.LabelFrame(
                dns_inner,
                text="VirusTotal",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            vt_dns_content_added = False # Flag for content within this frame

            # JARM Fingerprint
            if "jarm" in data and data["jarm"]:
                jarm_lf = tk.LabelFrame(dns_vt_frame, text="JARM Fingerprint", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                jarm_lf.pack(fill="x", padx=5, pady=5)
                
                # Create a simple treeview with one column
                jarm_container = tk.Frame(jarm_lf, bg=BACKGROUND_COLOR)
                jarm_container.pack(fill="both", expand=True)
                
                jarm_tv = ttk.Treeview(jarm_container, columns=("JARM",), show="headings", height=1)
                jarm_tv.heading("JARM", text="JARM Fingerprint", anchor="w")
                jarm_tv.column("JARM", width=600, anchor="w", stretch=True)
                jarm_tv.insert("", "end", values=(data["jarm"],))
                
                # Bind right-click menu
                bind_treeview_right_click_menu(jarm_tv)
                
                # Add scrollbar
                vsb = ttk.Scrollbar(jarm_container, orient="vertical", command=jarm_tv.yview)
                jarm_tv.configure(yscrollcommand=vsb.set)
                vsb.pack(side="right", fill="y")
                jarm_tv.pack(side="left", fill="both", expand=True)
                
                # Copy button
                btn_frame = tk.Frame(jarm_lf, bg=BACKGROUND_COLOR)
                btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
                
                copy_btn = tk.Button(
                    btn_frame, text="Copy", bg=BUTTON_COLOR, fg="white", font=FONT_BUTTON,
                    command=lambda: (
                        jarm_lf.clipboard_clear(),
                        jarm_lf.clipboard_append(data["jarm"]),
                        jarm_lf.update(),
                        copy_btn.config(text="Copied!"),
                        jarm_lf.after(2000, lambda: copy_btn.config(text="Copy"))
                    )
                )
                copy_btn.pack(side="left", padx=5)
                
                vt_dns_content_added = True

            # Last DNS Records
            if "last_dns_records" in data and data["last_dns_records"]:
                dns_vt_lr_frame = tk.LabelFrame(dns_vt_frame, text="Last DNS Records", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                dns_vt_lr_frame.pack(fill="x", padx=5, pady=5)
                create_treeview_for_dns_records(dns_vt_lr_frame, data["last_dns_records"])
                vt_dns_content_added = True

            # Categories in VirusTotal
            if "categories" in data and isinstance(data["categories"], dict) and data["categories"]:
                cat_lf = tk.LabelFrame(dns_vt_frame, text="Categories", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                cat_lf.pack(fill="x", padx=5, pady=5)
                create_treeview_for_categories(cat_lf, data["categories"])
                vt_dns_content_added = True

            # WHOIS from VirusTotal
            if "WHOIS Details" in data and data["WHOIS Details"]:
                raw_whois = data["WHOIS Details"]
                if isinstance(raw_whois, str) and raw_whois.strip():
                    whois_dict = parse_virustotal_whois(raw_whois) # parse_virustotal_whois is from ioc_topus.api.virustotal
                    if whois_dict:
                        whois_sub_lf_title = "WHOIS"
                        whois_sub_lf = tk.LabelFrame(dns_vt_frame, text=whois_sub_lf_title, font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                        whois_sub_lf.pack(fill="x", padx=5, pady=5)
                        create_whois_subtrees(whois_sub_lf, whois_dict)
                        vt_dns_content_added = True

            # Now, pack the main VirusTotal frame ONLY if content was added to it
            if vt_dns_content_added:
                dns_vt_frame.pack(fill="x", padx=5, pady=5)
                has_dns_data = True
            else:
                # If the frame was created but no content was ever added, destroy it
                dns_vt_frame.destroy()

        # Check for new Validin DNS data
        if "validin_dns_history" in data or "validin_dns_extra" in data:
            validin_dns_new_frame = tk.LabelFrame(
                dns_inner,
                text="Validin",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            
            validin_dns_new_content_added = False
            
            # DNS History
            if "validin_dns_history" in data:
                dns_hist_frame = tk.LabelFrame(
                    validin_dns_new_frame,
                    text="DNS History",
                    font=("Segoe UI", 11, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=5
                )
                dns_hist_frame.pack(fill="x", padx=5, pady=5)
                create_validin_dns_history_treeview(dns_hist_frame, data["validin_dns_history"])
                validin_dns_new_content_added = True
            
            # DNS Extra Records
            if "validin_dns_extra" in data:
                dns_extra_frame = tk.LabelFrame(
                    validin_dns_new_frame,
                    text="DNS Extra Records (MX, TXT, SOA, etc.)",
                    font=("Segoe UI", 11, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=5
                )
                dns_extra_frame.pack(fill="x", padx=5, pady=5)
                create_validin_dns_extra_treeview(dns_extra_frame, data["validin_dns_extra"])
                validin_dns_new_content_added = True
            
            if validin_dns_new_content_added:
                validin_dns_new_frame.pack(fill="x", padx=5, pady=10)
                has_dns_data = True


        # Validin - IP DNS History
        ip_dns_history_data = data.get('validin_ip_dns_history')
        if ip_dns_history_data and ip_dns_history_data.get("observations"):
            columns = {
                "hostname": {"text": "Hostname", "width": 400, "stretch": True},
                "record_type": {"text": "Record Type", "width": 100},
                "first_seen": {"text": "First Seen (UTC)", "width": 180},
                "last_seen": {"text": "Last Seen (UTC)", "width": 180},
            }
            create_dynamic_treeview(dns_inner, "Validin - IP DNS History", columns, ip_dns_history_data.get("observations"))
            has_dns_data = True

        # Validin - IP DNS Extra
        ip_dns_extra_data = data.get('validin_ip_dns_extra')
        if ip_dns_extra_data and ip_dns_extra_data.get("observations"):
            columns = {
                "type": {"text": "Type", "width": 120},
                "value": {"text": "Value", "width": 400, "stretch": True},
                "first_seen": {"text": "First Seen (UTC)", "width": 180},
                "last_seen": {"text": "Last Seen (UTC)", "width": 180},
            }
            create_dynamic_treeview(dns_inner, "Validin - IP DNS Extra Records", columns, ip_dns_extra_data.get("observations"))
            has_dns_data = True

        if not has_dns_data:
            ensure_not_empty(dns_inner)

        # ------------------------------
        # 4) RELATIONSHIPS tab
        #    => urlscan Downloaded Files, urlscan Contacted Network Indicators, plus VT relationships
        # ------------------------------
        
        relationship_data_found_in_tab = False # Track if ANYTHING is added to this tab
        # (B) VirusTotal Relationships Section
        vt_rels_data = data.get("relationships", {}) 
        vt_rel_content_added = False

        if vt_rels_data: # Check if there's any relationship data from VT
            relationships_vt_frame = tk.LabelFrame(
                relationships_inner,
                text="VirusTotal",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )

            # Contacted IPs
            contacted_ips_list = vt_rels_data.get("Contacted IPs", [])
            if contacted_ips_list:
                ips_lf = tk.LabelFrame(relationships_vt_frame, text="Contacted IPs", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                ips_lf.pack(fill="x", padx=5, pady=5)
                create_vt_relationship_treeview(ips_lf, contacted_ips_list, "Contacted IP")
                vt_rel_content_added = True
                relationship_data_found_in_tab = True

            # Contacted Domains
            contacted_domains_list = vt_rels_data.get("Contacted Domains", [])
            if contacted_domains_list:
                domains_lf = tk.LabelFrame(relationships_vt_frame, text="Contacted Domains", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                domains_lf.pack(fill="x", padx=5, pady=5)
                create_vt_relationship_treeview(domains_lf, contacted_domains_list, "Contacted Domain")
                vt_rel_content_added = True
                relationship_data_found_in_tab = True

            # Contacted URLs
            contacted_urls_list = vt_rels_data.get("Contacted URLs", [])
            if contacted_urls_list:
                urls_lf = tk.LabelFrame(relationships_vt_frame, text="Contacted URLs", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                urls_lf.pack(fill="x", padx=5, pady=5)
                create_vt_relationship_treeview(urls_lf, contacted_urls_list, "Contacted URL")
                vt_rel_content_added = True
                relationship_data_found_in_tab = True

            # Communicating Files
            communicating_files_list = vt_rels_data.get("Communicating Files", [])
            if communicating_files_list:
                comm_files_lf = tk.LabelFrame(relationships_vt_frame, text="Communicating Files", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                comm_files_lf.pack(fill="x", padx=5, pady=5)
                # This also likely uses create_treeview_for_related_hashes or a similar multi-column one
                create_communicating_files_treeview(comm_files_lf, communicating_files_list)
                vt_rel_content_added = True
                relationship_data_found_in_tab = True

            # Graph Data (IPs, URLs, Files from Graphs)
            graphs_output = vt_rels_data.get("graphs", {})
            if graphs_output:
                # Related IPs from Graphs
                related_graph_ips = graphs_output.get("ip_address", [])
                if related_graph_ips:
                    graph_ips_lf = tk.LabelFrame(relationships_vt_frame, text="Related IPs (from Graphs)", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                    graph_ips_lf.pack(fill="x", padx=5, pady=5)
                    create_vt_relationship_treeview(graph_ips_lf, related_graph_ips, "Related IP (Graph)")
                    vt_rel_content_added = True
                    relationship_data_found_in_tab = True
                
                # Related URLs from Graphs
                related_graph_urls = graphs_output.get("url", [])
                if related_graph_urls:
                    graph_urls_lf = tk.LabelFrame(relationships_vt_frame, text="Related URLs (from Graphs)", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                    graph_urls_lf.pack(fill="x", padx=5, pady=5)
                    create_vt_relationship_treeview(graph_urls_lf, related_graph_urls, "Related URL (Graph)")
                    vt_rel_content_added = True
                    relationship_data_found_in_tab = True

                # Related Files from Graphs
                related_graph_files = graphs_output.get("file", []) # This should be a list of dicts
                if related_graph_files:
                    graph_files_lf = tk.LabelFrame(relationships_vt_frame, text="Related Files (from Graphs)", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                    graph_files_lf.pack(fill="both", expand=True, padx=5, pady=5)
                    create_graph_related_files_treeview(graph_files_lf, related_graph_files)
                    vt_rel_content_added = True
                    relationship_data_found_in_tab = True

            # Referrer Files (uses the enhanced create_communicating_files_treeview logic)
            referrer_files_data = vt_rels_data.get("Referrer Files", [])
            if referrer_files_data:
                ref_files_lf = tk.LabelFrame(relationships_vt_frame, text="Referrer Files", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=5)
                ref_files_lf.pack(fill="both", expand=True, padx=5, pady=5)
                create_communicating_files_treeview(ref_files_lf, referrer_files_data) # Reusing this for its detailed display
                vt_rel_content_added = True
                relationship_data_found_in_tab = True


            # Pack the main VirusTotal relationships frame only if content was added
            if vt_rel_content_added:
                # This check should be done once after all potential VT relationship sections
                if not relationships_vt_frame.winfo_ismapped(): # Only pack if not already packed
                    relationships_vt_frame.pack(fill="x", padx=5, pady=5)
            else:
                if 'relationships_vt_frame' in locals() and relationships_vt_frame.winfo_exists():
                     relationships_vt_frame.destroy()

            # Pack the main VirusTotal relationships frame only if content was added
            if vt_rel_content_added:
                relationships_vt_frame.pack(fill="x", padx=5, pady=5)
            else:
                # If the frame was created but nothing put in it, destroy it
                if 'relationships_vt_frame' in locals():
                     relationships_vt_frame.destroy()

        # (A) URLScan Relationships Section - Conditional Creation & Packing
        st_rel_content_added = False
        # Check if st_sections potentially holds relationship data
        if st_sections and ("urlscan Downloaded Files" in st_sections or "urlscan Contacted Network Indicators" in st_sections):
            # Only create the main ST frame if there's potentially content
            relationships_st_frame = tk.LabelFrame(relationships_inner, text="URLScan", font=("Segoe UI", 12, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)

            if "urlscan Downloaded Files" in st_sections:
                dl_data = st_sections["urlscan Downloaded Files"].get("downloaded_data", [])
                # Check if data is not empty and not the placeholder message
                if dl_data and not (len(dl_data)==1 and dl_data[0].get("downloaded_filename")=="No artifacts"):
                    rlf_dl = tk.LabelFrame( relationships_st_frame, text="Downloaded Files", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                    rlf_dl.pack(fill="x", padx=5, pady=5)
                    create_multi_downloaded_treeview(rlf_dl, dl_data)
                    st_rel_content_added = True
                    relationship_data_found_in_tab = True

            if "urlscan Contacted Network Indicators" in st_sections:
                cni_data = st_sections["urlscan Contacted Network Indicators"].get("contacted_items", [])
                if cni_data:
                    rlf_cni = tk.LabelFrame( relationships_st_frame, text="Contacted Network Indicators", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                    rlf_cni.pack(fill="x", padx=5, pady=5)
                    create_multi_contacted_indicators_treeview(rlf_cni, cni_data)
                    st_rel_content_added = True
                    relationship_data_found_in_tab = True

            # Pack the main ST frame only if sub-content was added
            if st_rel_content_added:
                relationships_st_frame.pack(fill="x", padx=5, pady=5)
            else:
                 relationships_st_frame.destroy()



        # Finally, check if the Relationships tab is empty overall
        if not relationship_data_found_in_tab:
             ensure_not_empty(relationships_inner) # Add 'No data' label if tab is empty

        # 5) WEB ANALYSIS tab
        #    => "urlscan Webpage Analysis", "urlscan HTTP Response" (including body hashes & so on)
        # ------------------------------
        has_web_data = False

            # First, create two sub-frames under web_analysis_inner:
        if ioc_type_ in ("url", "domain", "ip_address", "fingerprint_hash"):
            if ioc_type_ == "url":
                # --- VirusTotal portion ---
                vt_web_frame = tk.LabelFrame(
                    web_analysis_inner,
                    text="VirusTotal",
                    font=("Segoe UI", 12, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=10
                )
                vt_web_frame.pack(fill="x", padx=5, pady=5)
                vt_web_content_added = False
                # Show “http_response_data” if present
                if "http_response_data" in data:
                    vt_http_lf = tk.LabelFrame(
                        vt_web_frame,
                        text="HTTP Response Data",
                        font=("Segoe UI", 11, "bold"),
                        bg=BACKGROUND_COLOR,
                        fg=TEXT_COLOR,
                        padx=10,
                        pady=10
                    )
                    vt_http_lf.pack(fill="x", padx=5, pady=5)
                    create_httpresp_treeview_dynamic(vt_http_lf, data["http_response_data"])
                    vt_web_content_added = True

                # Show “outgoing_links” if present
                if "outgoing_links" in data:
                    vt_outlinks_lf = tk.LabelFrame(
                        vt_web_frame,
                        text="Outgoing Links",
                        font=("Segoe UI", 11, "bold"),
                        bg=BACKGROUND_COLOR,
                        fg=TEXT_COLOR,
                        padx=10,
                        pady=10
                    )
                    vt_outlinks_lf.pack(fill="x", padx=5, pady=5)

                    links_list = data["outgoing_links"]
                    create_treeview_for_single_column_links(
                        vt_outlinks_lf,
                        links_list,
                        column_header="Outgoing Link")
                    vt_web_content_added = True
                if vt_web_content_added:
                    vt_web_frame.pack(fill="x", padx=5, pady=5)
                    has_web_data = True
                elif vt_web_frame.winfo_exists():
                    vt_web_frame.destroy()
            # --- urlscan portion always shown for domain/ip/url if st_sections has it
            st_web_frame = tk.LabelFrame(
                web_analysis_inner,
                text="URLScan",
                font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR,
                fg=TEXT_COLOR,
                padx=10,
                pady=10
            )
            st_web_frame.pack(fill="x", padx=5, pady=5)
            st_web_content_added = False
            if "urlscan Webpage Analysis" in st_sections:
                wpa_section = st_sections["urlscan Webpage Analysis"]
                analysis_data = wpa_section.get("analysis", [])
                if analysis_data:
                    has_web_data = True
                    wpa_frame = tk.LabelFrame(
                        st_web_frame,
                        text="Webpage Analysis",
                        font=("Segoe UI", 11, "bold"),
                        bg=BACKGROUND_COLOR,
                        fg=TEXT_COLOR,
                        padx=10,
                        pady=10
                    )
                    wpa_frame.pack(fill="x", padx=5, pady=5)
                    create_multi_webpage_analysis_treeview(wpa_frame, analysis_data)
                st_web_content_added = True
            if "urlscan HTTP Response" in st_sections:
                uhr_section = st_sections["urlscan HTTP Response"]
                http_items_data = uhr_section.get("http_items", [])
                if http_items_data:
                    uhr_frame = tk.LabelFrame(
                        st_web_frame,
                        text="HTTP Response",
                        font=("Segoe UI", 11, "bold"),
                        bg=BACKGROUND_COLOR,
                        fg=TEXT_COLOR,
                        padx=10,
                        pady=10
                    )
                    uhr_frame.pack(fill="x", padx=5, pady=5)
                    create_multi_urlscan_httpresp_treeview(uhr_frame, http_items_data)
                st_web_content_added = True
            if "urlscan response header" in st_sections:
                rhead_data = st_sections["urlscan response header"].get("raw_header_items", [])
                if rhead_data:
                    rhead_frame = tk.LabelFrame(
                        st_web_frame,
                        text="Raw Response Header",
                        font=("Segoe UI", 11, "bold"),
                        bg=BACKGROUND_COLOR,
                        fg=TEXT_COLOR,
                        padx=10,
                        pady=10
                    )
                    rhead_frame.pack(fill="x", padx=5, pady=5)

                    pretty_text = json.dumps(rhead_data, indent=2)
                    create_textbox_with_scroll(
                        rhead_frame,
                        pretty_text,
                        bg_color="#FFFFFF",
                        font_style=FONT_TREE,
                        width=60,
                        height=12,
                        include_copy_button=True
                    )
                st_web_content_added = True
            if st_web_content_added:
                st_web_frame.pack(fill="x", padx=5, pady=5)
                has_web_data = True
            elif st_web_frame.winfo_exists():
                st_web_frame.destroy()


            # --- Validin Web Pivots Section ---
            raw_validin_data = data.get("validin_dns", {})
            val_dns_grouped = raw_validin_data.get("validin_dns_grouped")
            val_dns_lists = raw_validin_data.get("validin_dns_lists")
            
            validin_web_frame_content_added = False # Specific to Validin's contribution to this tab
            if val_dns_grouped or val_dns_lists: # If there's any Validin data
                validin_web_frame = tk.LabelFrame(
                    web_analysis_inner, # Parent is the main tab frame
                    text="Validin Web Pivots",
                    font=("Segoe UI", 12, "bold"),
                    bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10
                ) # Define
                
                # Process Grouped Data
                if val_dns_grouped:
                    validin_grouped_subframe = tk.LabelFrame(
                        validin_web_frame, text="General Info", # Parent is validin_web_frame
                        font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=5, pady=5
                    )
                    grouped = group_validin_headers(val_dns_grouped)
                    if grouped:
                        validin_grouped_subframe.pack(fill="x", padx=5, pady=5)
                        for group_name, group_data_items in grouped.items(): # Renamed group_data to group_data_items
                            if group_data_items:
                                group_frame = tk.LabelFrame(validin_grouped_subframe, text=group_name, font=("Segoe UI", 10, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=5, pady=5)
                                group_frame.pack(fill="x", padx=5, pady=5)
                                create_validin_treeview(group_frame, group_data_items, group_name)
                                validin_web_frame_content_added = True 
                
                # Process List Data
                if val_dns_lists:
                    validin_lists_subframe = tk.LabelFrame(
                        validin_web_frame, text="Hashes & Hosts", # Parent is validin_web_frame
                        font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=5, pady=5
                    )
                    list_data_found_for_validin_lists_subframe = False
                    for header, value_list in val_dns_lists.items():
                        if value_list:
                            if not list_data_found_for_validin_lists_subframe:
                                validin_lists_subframe.pack(fill="x", padx=5, pady=5)
                                list_data_found_for_validin_lists_subframe = True
                            list_frame = tk.LabelFrame(validin_lists_subframe, text=header, font=("Segoe UI", 10, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=5, pady=5)
                            list_frame.pack(fill="x", padx=5, pady=5)
                            create_treeview_for_single_column_links(list_frame, value_list, column_header=header)
                            validin_web_frame_content_added = True
                
                if validin_web_frame_content_added:
                    validin_web_frame.pack(fill="x", padx=5, pady=10)
                    has_web_data = True # Update the overall tab flag
                elif 'validin_web_frame' in locals() and validin_web_frame.winfo_exists():
                    validin_web_frame.destroy()
        

            # --- Validin Hash Pivots Section ---
            raw_validin_hash_data = data.get("validin_hash_pivots", {})
            pivot_data = raw_validin_hash_data.get("pivot_data", [])

            validin_hash_frame_content_added = False
            if pivot_data:
                validin_hash_frame = tk.LabelFrame(
                    web_analysis_inner,
                    text="Validin Hash Pivots",
                    font=("Segoe UI", 12, "bold"),
                    bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10
                )
                
                # Create container for treeview and scrollbars
                tree_container = tk.Frame(validin_hash_frame, bg=BACKGROUND_COLOR)
                tree_container.pack(fill="both", expand=True, pady=5)
                
                # Create treeview with columns
                columns = ("Indicator", "Type", "First Seen", "Last Seen")
                hash_pivot_tv = ttk.Treeview(tree_container, columns=columns, show="headings", height=15)
                
                # Configure columns
                hash_pivot_tv.heading("Indicator", text="Indicator", anchor="w")
                hash_pivot_tv.heading("Type", text="Type", anchor="w")
                hash_pivot_tv.heading("First Seen", text="First Seen", anchor="w")
                hash_pivot_tv.heading("Last Seen", text="Last Seen", anchor="w")
                
                hash_pivot_tv.column("Indicator", width=400, anchor="w", stretch=True, minwidth=300)
                hash_pivot_tv.column("Type", width=100, anchor="w", stretch=False, minwidth=80)
                hash_pivot_tv.column("First Seen", width=200, anchor="w", stretch=False, minwidth=150)
                hash_pivot_tv.column("Last Seen", width=200, anchor="w", stretch=False, minwidth=150)
                
                # Helper function to convert epoch to readable date
                def epoch_to_date(epoch_time):
                    try:
                        if epoch_time:
                            return datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        return ""
                    except:
                        return str(epoch_time)
                
                # Insert data
                for pivot in pivot_data:
                    indicator = pivot.get("indicator", "")
                    ind_type = pivot.get("indicator_type", "")
                    first_seen = epoch_to_date(pivot.get("first_seen", 0))
                    last_seen = epoch_to_date(pivot.get("last_seen", 0))
                    
                    hash_pivot_tv.insert("", "end", values=(indicator, ind_type, first_seen, last_seen))
                
                # Add scrollbars
                vsb = ttk.Scrollbar(tree_container, orient="vertical", command=hash_pivot_tv.yview)
                hash_pivot_tv.configure(yscrollcommand=vsb.set)
                vsb.pack(side="right", fill="y")
                
                hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=hash_pivot_tv.xview)
                hash_pivot_tv.configure(xscrollcommand=hsb.set)
                hsb.pack(side="bottom", fill="x")
                
                hash_pivot_tv.pack(side="left", fill="both", expand=True)
                
                # Bind right-click menu for pivoting
                bind_treeview_right_click_menu(hash_pivot_tv)
                
                # Add Copy All button (on the left, below the treeview)
                btn_frame = tk.Frame(validin_hash_frame, bg=BACKGROUND_COLOR)
                btn_frame.pack(side="bottom", anchor="sw", fill="x", pady=(3,0))
                
                def copy_all_hash_pivots():
                    lines = []
                    lines.append("Indicator\tType\tFirst Seen\tLast Seen")
                    for child_id in hash_pivot_tv.get_children():
                        vals = hash_pivot_tv.item(child_id, "values")
                        lines.append("\t".join(str(v) for v in vals))
                    joined = "\n".join(lines)
                    validin_hash_frame.clipboard_clear()
                    validin_hash_frame.clipboard_append(joined)
                    validin_hash_frame.update()
                    copy_btn.config(text="Copied!")
                    validin_hash_frame.after(2000, lambda: copy_btn.config(text="Copy All"))
                
                copy_btn = tk.Button(
                    btn_frame, text="Copy All", bg="#9370DB", fg="white",
                    font=("Segoe UI", 10, "bold"), command=copy_all_hash_pivots
                )
                copy_btn.pack(side="left", padx=5)
                
                validin_hash_frame_content_added = True
                
                if validin_hash_frame_content_added:
                    validin_hash_frame.pack(fill="x", padx=5, pady=10)
                    has_web_data = True
                elif 'validin_hash_frame' in locals() and validin_hash_frame.winfo_exists():
                    validin_hash_frame.destroy()

        domain_crawl_data = data.get('validin_domain_crawl_history')
        if domain_crawl_data and domain_crawl_data.get("observations"):
            columns = {
                "date": {"text": "Date", "width": 150},
                "scheme": {"text": "Scheme", "width": 80},
                "port": {"text": "Port", "width": 60},
                "ip": {"text": "IP", "width": 120},
                "title": {"text": "Page Title", "width": 200, "stretch": True},
                "status": {"text": "Status", "width": 120},
                "server": {"text": "Server", "width": 150},
                "content_type": {"text": "Content-Type", "width": 150},
                "location_redirect": {"text": "Redirect Location", "width": 200},
                "length": {"text": "Length", "width": 80},
                "body_hash": {"text": "Body Hash", "width": 200},
                "header_hash": {"text": "Header Hash", "width": 150},
                "banner_hash": {"text": "Banner Hash", "width": 150},
                "cert_fingerprint": {"text": "Cert Fingerprint", "width": 200},
                "cert_domains": {"text": "Cert Domains", "width": 150},
                "jarm": {"text": "JARM", "width": 200},
                "external_links": {"text": "External Links", "width": 150},
                "class_0_hash": {"text": "Class 0 Hash", "width": 150},
                "class_1_hash": {"text": "Class 1 Hash", "width": 150},
            }
            create_dynamic_treeview(web_analysis_inner, "Validin - Domain Crawl History", columns, domain_crawl_data.get("observations"))
            has_web_data = True

        # Validin - IP Crawl History
        ip_crawl_data = data.get('validin_ip_crawl_history')
        if ip_crawl_data and ip_crawl_data.get("observations"):
            columns = {
                "last_seen": {"text": "Last Seen (UTC)", "width": 180},
                "port": {"text": "Port", "width": 60},
                "scheme": {"text": "Scheme", "width": 70},
                "banner": {"text": "Banner", "width": 350, "stretch": True},
                "banner_0_hash": {"text": "Banner Hash (MD5)", "width": 280},
                "header_hash": {"text": "Header Hash", "width": 280},
                "start_line": {"text": "Start Line", "width": 300},
                "error": {"text": "Error", "width": 250},
                "ip": {"text": "IP", "width": 120},
            }
            create_dynamic_treeview(web_analysis_inner, "Validin - IP Crawl History", columns, ip_crawl_data.get("observations"))
            has_web_data = True
        # Final check for Web Analysis tab
        if not has_web_data:
            ensure_not_empty(web_analysis_inner)

        # ------------------------------
        # 6) BEHAVIORAL FILE ANALYSIS tab => dynamic analysis
        # ------------------------------
        # Clear previous content from dynamic_analysis_inner
        for w in dynamic_analysis_inner.winfo_children():
            w.destroy()
        behavioral_analysis_added = False # Flag to track if anything was actually added to this tab
        
        # Only attempt to populate if it's a file hash OR if dynamic_data (for other types) might exist from merged results.
        # However, typically, top-level dynamic_analysis for IP/URL/Domain is not about file behavior.
        if ioc_type_ == "file_hash" or (dynamic_data and ioc_type_ != "file_hash"): # Check if dynamic_data has content even for non-files
            bf_vt_frame = tk.LabelFrame(
                dynamic_analysis_inner, text="VirusTotal Behavioral", font=("Segoe UI", 12, "bold"),
                bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10
            )
            vt_behavioral_content_found_in_frame = False # Track for the VT sub-frame

            if dynamic_data: # Check if the main dynamic_analysis dict exists and has content
                # Sandbox Verdicts
                sandbox_verdicts_data = dynamic_data.get("sandbox_verdicts", [])
                if sandbox_verdicts_data: # Check if the list is not empty
                    sb_frame = tk.LabelFrame(bf_vt_frame, text="Sandbox Verdicts", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                    sb_frame.pack(fill="x", padx=5, pady=5)
                    create_treeview_for_sandbox_verdicts(sb_frame, sandbox_verdicts_data)
                    vt_behavioral_content_found_in_frame = True

                # Sigma Analysis Results
                sigma_results_data = dynamic_data.get("sigma_analysis_results", [])
                if sigma_results_data:
                    sigma_frame = tk.LabelFrame(bf_vt_frame, text="Sigma Analysis Results", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                    sigma_frame.pack(fill="x", padx=5, pady=5)
                    create_treeview_for_sigma(sigma_frame, sigma_results_data)
                    vt_behavioral_content_found_in_frame = True

                # Crowdsourced IDS Results
                crowdsourced_ids_data = dynamic_data.get("crowdsourced_ids_results", [])
                if crowdsourced_ids_data:
                    csc_frame = tk.LabelFrame(bf_vt_frame, text="Crowdsourced IDs", font=("Segoe UI", 11, "bold"), bg=BACKGROUND_COLOR, fg=TEXT_COLOR, padx=10, pady=10)
                    csc_frame.pack(fill="x", padx=5, pady=5)
                    create_treeview_for_crowdsourced_ids(csc_frame, crowdsourced_ids_data)
                    vt_behavioral_content_found_in_frame = True

                # Behavior Summary Details (most relevant for files)
                summary_details = dynamic_data.get("behavior_summary_details", {})
                # Check if it's not empty and doesn't *only* contain the placeholder message
                if summary_details and not (len(summary_details) == 1 and "message" in summary_details):
                    create_behavior_summary_subtrees(bf_vt_frame, summary_details) # This packs its own sub-frames
                    vt_behavioral_content_found_in_frame = True
            
            if vt_behavioral_content_found_in_frame:
                bf_vt_frame.pack(fill="both", expand=True, padx=5, pady=5)
                behavioral_analysis_added = True # Mark the whole tab as having content
            elif bf_vt_frame.winfo_exists(): # If frame was created but no content
                bf_vt_frame.destroy()

        # Ensure "No data" message if nothing was added to this tab
        if not behavioral_analysis_added:
            ensure_not_empty(dynamic_analysis_inner)
        # ------------------------------
        # 7) FILE ANALYSIS tab => static analysis if ioc_type_ == "file_hash"
        # ------------------------------
        for w in static_analysis_inner.winfo_children(): # Clear previous content
            w.destroy()
        has_static_analysis_data = False # Flag for this tab

        if ioc_type_ == "file_hash":
            # Define the keys that constitute static file analysis data
            static_file_keys = [
                "File Type", "magic", "size", "trid", "PE Metadata",
                "Dot Net Assembly", "elf_info_header", "linkers", "compilers", "tools",
                "packers", "installers", "ssdeep", "tlsh", "permhash", "authentihash",
                "telfhash", "names", "signature_info", "verified", "signers", "pkcs7_opusinfo"
                # Add any other keys that create_vertical_static_treeview might display
            ]
            # Check if 'data' contains any of these keys AND that the data for those keys is not empty/falsey
            if any(key in data and data[key] for key in static_file_keys):
                sa_frame = tk.LabelFrame(
                    static_analysis_inner,
                    text="Static File Analysis",
                    font=("Segoe UI", 12, "bold"),
                    bg=BACKGROUND_COLOR,
                    fg=TEXT_COLOR,
                    padx=10,
                    pady=10
                )
                sa_frame.pack(fill="x", padx=5, pady=5)
                create_vertical_static_treeview(sa_frame, data)
                has_static_analysis_data = True
            # If no relevant keys have meaningful data, sa_frame is not created, flag remains False
        
        # Call ensure_not_empty if no static analysis data was added for any reason
        if not has_static_analysis_data:
            ensure_not_empty(static_analysis_inner)

        ioc_fields_scrolled.canvas.yview_moveto(0)
        certificates_scrolled.canvas.yview_moveto(0)
        dns_scrolled.canvas.yview_moveto(0)
        relationships_scrolled.canvas.yview_moveto(0)
        web_analysis_scrolled.canvas.yview_moveto(0)
        dynamic_analysis_scrolled.canvas.yview_moveto(0)
        static_analysis_scrolled.canvas.yview_moveto(0)



        # 5. Reset scroll positions for all tabs
        for scroll_frame in [
            ioc_fields_scrolled, static_analysis_scrolled, relationships_scrolled,
            dynamic_analysis_scrolled, certificates_scrolled, dns_scrolled,
            web_analysis_scrolled
        ]:
            scroll_frame.canvas.yview_moveto(0)
            scroll_frame.canvas.xview_moveto(0) # Also reset horizontal scroll

        status_bar.config(text=f"Details displayed for IOC: {ioc_val}")

    # ------------------------------------------------------------------------
    # 5) CONSTRUCT THE PRIMARY UI LAYOUT
    # ------------------------------------------------------------------------
    mode_notebook = ttk.Notebook(root)
    mode_notebook.pack(fill="both", expand=True)

    indicator_mode_frame = ttk.Frame(mode_notebook)
    mode_notebook.add(indicator_mode_frame, text="Indicator Search Mode")

    main_paned = ttk.Panedwindow(indicator_mode_frame, orient="vertical")
    main_paned.pack(fill="both", expand=True)

    top_frame = ttk.Frame(main_paned)
    bottom_frame = ttk.Frame(main_paned)
    main_paned.add(top_frame, weight=1)
    main_paned.add(bottom_frame, weight=3)

    tree_frame = tk.Frame(top_frame, bg=BACKGROUND_COLOR)
    tree_frame.pack(fill="both", expand=True, padx=20, pady=10)

    columns = ("IOC", "Sources")
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

    tree.heading("IOC", text="IOC")
    tree.heading("Sources", text="Sources")

    tree.column("IOC", width=400, anchor="w")
    tree.column("Sources", width=300, anchor="w")
    tree.pack(side="left", fill="both", expand=True)

    bind_treeview_right_click_menu(tree)

    tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=tree_scroll.set)
    tree_scroll.pack(side="right", fill="y")

    tree.tag_configure('oddrow', background="#FFFFFF")
    tree.tag_configure('evenrow', background="#F8F8F8")
    tree.tag_configure('malicious', background="#FFD1D1")
    tree.tag_configure('clean', background="#FFFFFF")

    # The bottom tab notebook
    notebook = ttk.Notebook(bottom_frame)
    notebook.pack(fill="both", expand=True, padx=20, pady=10)

    ioc_fields_frame = ttk.Frame(notebook)
    static_analysis_frame = ttk.Frame(notebook)
    relationships_frame = ttk.Frame(notebook)
    dynamic_analysis_frame = ttk.Frame(notebook)
    certificates_frame = ttk.Frame(notebook)
    dns_frame = ttk.Frame(notebook)
    web_analysis_frame = ttk.Frame(notebook)

    notebook.add(ioc_fields_frame, text="Indicator Details")
    notebook.add(static_analysis_frame, text="File Analysis")
    notebook.add(relationships_frame, text="Relationships")
    notebook.add(dynamic_analysis_frame, text="Behavioral File Analysis")
    notebook.add(certificates_frame, text="Certificates")
    notebook.add(dns_frame, text="DNS Analysis")
    notebook.add(web_analysis_frame, text="Web Analysis")

    # The scrolled frames inside each tab
    ioc_fields_scrolled = SmoothScrolledFrame(ioc_fields_frame, bg_color=BACKGROUND_COLOR)
    ioc_fields_scrolled.pack(fill="both", expand=True)
    ioc_fields_inner = ioc_fields_scrolled.get_inner_frame()

    static_analysis_scrolled = SmoothScrolledFrame(static_analysis_frame, bg_color=BACKGROUND_COLOR)
    static_analysis_scrolled.pack(fill="both", expand=True)
    static_analysis_inner = static_analysis_scrolled.get_inner_frame()

    relationships_scrolled = SmoothScrolledFrame(relationships_frame, bg_color=BACKGROUND_COLOR)
    relationships_scrolled.pack(fill="both", expand=True)
    relationships_inner = relationships_scrolled.get_inner_frame()

    dynamic_analysis_scrolled = SmoothScrolledFrame(dynamic_analysis_frame, bg_color=BACKGROUND_COLOR)
    dynamic_analysis_scrolled.pack(fill="both", expand=True)
    dynamic_analysis_inner = dynamic_analysis_scrolled.get_inner_frame()

    certificates_scrolled = SmoothScrolledFrame(certificates_frame, bg_color=BACKGROUND_COLOR)
    certificates_scrolled.pack(fill="both", expand=True)
    certificates_inner = certificates_scrolled.get_inner_frame()

    dns_scrolled = SmoothScrolledFrame(dns_frame, bg_color=BACKGROUND_COLOR)
    dns_scrolled.pack(fill="both", expand=True)
    dns_inner = dns_scrolled.get_inner_frame()

    web_analysis_scrolled = SmoothScrolledFrame(web_analysis_frame, bg_color=BACKGROUND_COLOR)
    web_analysis_scrolled.pack(fill="both", expand=True)
    web_analysis_inner = web_analysis_scrolled.get_inner_frame()

    # ------------------------------------------------------------------------
    # 6) BOTTOM BAR: STATUS + PROGRESS BAR, PLUS IO ENTRY FRAME
    # ------------------------------------------------------------------------
    bottom_bar_frame = tk.Frame(root, bg="#D3D3D3")
    bottom_bar_frame.pack(side="bottom", fill="x")

    status_bar = tk.Label(
        bottom_bar_frame,
        text="Welcome to IOC-Topus",
        bd=1,
        relief=tk.SUNKEN,
        anchor="w",
        font=FONT_STATUS,
        bg="#D3D3D3"
    )
    status_bar.pack(side="left", fill="x", expand=True)

    progress_bar = ttk.Progressbar(root, mode='indeterminate')
    progress_bar.pack(side="bottom", fill="x", padx=20, pady=5)

    top_actions_frame = tk.Frame(root, bg=HEADER_COLOR, pady=5)
    top_actions_frame.pack(fill="x")
    top_actions_frame.columnconfigure(0, weight=1)
    top_actions_frame.columnconfigure(7, weight=1)

    add_button = tk.Button(
        top_actions_frame,
        text=" Search",
        command=open_search_popup,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold"),  # bigger, bolder
        relief="raised"
    )
    # Place it in column=1 instead of 0
    add_button.grid(row=0, column=1, padx=10, pady=5)

    upload_button = tk.Button(
        top_actions_frame,
        text=" Bulk Search",
        command=open_upload_popup,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold"),
        relief="raised"
    )
    upload_button.grid(row=0, column=2, padx=10, pady=5)

    export_button = tk.Button(
        top_actions_frame,
        text=" Export",
        command=export_to_csv,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold"),
        relief="raised"
    )
    export_button.grid(row=0, column=3, padx=10, pady=5)

    submit_button = tk.Button(
        top_actions_frame,
        text=" Submit",
        command=open_submit_popup,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold"),
        relief="raised"
    )
    submit_button.grid(row=0, column=4, padx=10, pady=5)

    set_api_button = tk.Button(
        top_actions_frame,
        text=" Set API Keys",
        command=open_api_key_popup,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold")
    )
    set_api_button.grid(row=0, column=5, padx=10, pady=5)

    usage_button = tk.Button(
        top_actions_frame,
        text=" API Usage",
        command=open_api_usage_popup,
        bg=BUTTON_COLOR,
        fg="white",
        font=("Segoe UI", 12, "bold")
    )
    usage_button.grid(row=0, column=6, padx=10, pady=5)

    # Finally, bind the main tree event to show_details
    tree.bind("<<TreeviewSelect>>", show_details)

    # ------------------------------------------------------------------------
    # 7) MAIN LOOP
    # ------------------------------------------------------------------------
    return root

# ────────────────────────────────────────────────────────────
# 4) Public launcher
# ────────────────────────────────────────────────────────────
def open_gui(*, test_mode: bool = False):
    """
    Launch the IOCTopus Tkinter GUI.

    In normal runs ``open_gui()`` blocks inside ``mainloop()``.
    In unit-tests call ``open_gui(test_mode=True)`` so the window
    is constructed and immediately returned without starting the
    event loop.
    """
    root = build_gui()
    if not test_mode:
        root.mainloop()
    return root

if __name__ == "__main__":
    open_gui()
