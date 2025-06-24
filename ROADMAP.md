# 🐙 IOCTopus Project Roadmap

This document outlines the current state and future direction of IOCTopus. Our goal is to create a comprehensive, multi-faceted tool for security researchers that bridges the gap between reactive IOC analysis and proactive infrastructure hunting.

---

### ✅ **Current Accomplishments (v1.0)**

The initial version of IOCTopus establishes a powerful foundation for IOC analysis with a focus on speed and data correlation.

-   **Core GUI Framework**: A robust and responsive graphical interface for easy interaction.
-   **Secure Encrypted API Key Storage**: End-to-end encryption for user API keys, ensuring they are never stored in plaintext.
-   **Core API Integrations**:
    -   **VirusTotal**: Comprehensive file, IP, domain, and URL lookups.
    -   **urlscan.io**: Web page analysis, technology fingerprinting, and network request data.
    -   **Validin**: IP and domain intelligence and context.
-   **Bulk IOC Processing**: Ability to analyze a list of indicators in a single operation.
-   **CSV Export**: Foundational capability to export collected data.

---

### 🚀 **Future Milestones**

This is where IOCTopus is headed next with development. The program is organized into two primary "modes" of operation.

#### **Phase 1: IOC Search Mode Enhancements**

The immediate focus is on enriching the existing IOC analysis capabilities.

-   **Revise Exporting Capabilities**: Overhaul the CSV export feature to produce more structured, actionable reports with prettier formatting and customizable output.
-   **Integrate Validin Hash Pivoting**: Leverage Validin's API to pivot from host responses for fingerprints and hashes (e.g., JARM, certificate hash, banner and other header hashes)
-   **Integrate Criminal IP API**: Add another source of IP and domain intelligence, providing a more complete picture of network indicators.
-   **Integrate Sandbox APIs**:
    -   **CrowdStrike Falcon Sandbox**
    -   **Recorded Future Tria.ge**
-   **Integrate abuse.ch telemetry**

#### **Phase 2: Infrastructure Hunting Mode**

This major new feature will transform IOCTopus from a reactive tool to a proactive discovery engine. The goal is to allow researchers to hunt for adversary infrastructure at scale.

-   **Unified Query Language**: Develop a simplified, powerful query syntax that translates a single search into the native languages of multiple internet asset repositories.
-   **Core Asset API Integrations**:
    -   Criminal IP
    -   Censys
    -   FOFA
    -   Shodan
-   **Data Correlation Engine**: Intelligently link results from asset queries back to IOCs for deeper context and discovery.