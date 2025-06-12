# 🐙 IOCTopus - Your Threat Intelligence Swiss Army Knife

<p align="center">
  <img src="https://raw.githubusercontent.com/scoope3/ioc-topus/main/docs/logo_placeholder.png" alt="IOCTopus Logo" width="200"/>
</p>

**Tired of juggling a dozen browser tabs for IOC analysis? IOCTopus is a fast, powerful, GUI-based threat intelligence aggregator that brings the data to you.**

IOCTopus streamlines your workflow by fetching, correlating, and displaying rich data for Indicators of Compromise (IPs, domains, URLs, and file hashes) from the most trusted APIs in threat intelligence.

---

### Key Features

-   **All-in-One Interface**: Look up IOCs from VirusTotal, urlscan.io, and Validin without leaving the application.
-   **Bulk Analysis**: Feed it a list of IOCs and let it do the hard work, with results neatly organized for review.
-   **Secure API Key Storage**: Your API keys are **encrypted at rest** on your local machine using a master key, so they are never stored in plaintext.
-   **Submit & Detonate**: Submit URLs and files for fresh analysis and sandboxing on VirusTotal and urlscan.io.
-   **Rich, Correlated Data**: View detailed file attributes, network communication, behavioral analysis, and submitted URLs in easy-to-navigate tabs.
-   **Export to CSV**: Easily export all collected data for reporting or further analysis in other tools.

---

### 🛡️ Secure by Design: API Key Encryption

We take security seriously. When you enter your API keys into IOCTopus:
1.  A master encryption key is generated and stored securely in your user home directory (`~/.ioc_topus_key`).
2.  Your API keys are encrypted using this master key.
3.  The **encrypted keys** are saved to a local `.env` file.
4.  At runtime, the application decrypts the keys into memory for use.

**Your API keys are never stored in plaintext on your disk.**

---

### Installation

IOCTopus is a standard Python application.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/scoope3/ioc-topus.git](https://github.com/scoope3/ioc-topus.git)
    cd ioc-topus
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**

    ```bash
    pip install click requests pillow python-dotenv cryptography
    ```

---

### Usage

1.  **Run the application:**
    ```bash
    python -m ioc_topus.cli gui
    ```

2.  **Set Your API Keys:**
    -   On first launch, click the **"Set API Keys"** button.
    -   Enter your keys for VirusTotal, urlscan.io, and Validin.
    -   Click **"Apply"**. Your keys will be encrypted and saved for future sessions.

3.  **Start Analyzing!**
    -   Use the **Search** or **Bulk Search** buttons to look up indicators.
    -   Use the **Submit** button to send new URLs or files for analysis.
    -   Use the **Export** widget to export your search results.
    -   Click on any IOC in the top results list to see detailed, categorized data in the tabs below.

---
*Disclaimer: This tool is provided for educational and research purposes only. The user is responsible for adhering to the terms of service of all integrated API providers.*
