# 🐙 IOCTopus Project Roadmap

This document outlines the current state and future direction of IOCTopus. The goal is to create a comprehensive, multi-faceted tool for security researchers that bridges the gap between reactive IOC analysis and proactive infrastructure hunting.

---

### ✅ **Current Accomplishments (v1.0)**

The initial version of IOCTopus establishes a powerful foundation for IOC analysis with a focus on speed and data correlation.

-   **Core GUI Framework**: A robust and responsive graphical interface for easy interaction.
-   **Secure Encrypted API Key Storage**: End-to-end encryption for user API keys, ensuring they are never stored in plaintext.
-   **Core API Integrations**:
   -   **VirusTotal**: Comprehensive file, IP, domain, and URL lookups.
   -   **urlscan.io**: Web page analysis, technology fingerprinting, and network request data.
   -   **Validin**: IP and domain intelligence and context.
   -   **Validin Hash Pivoting**: ✅ Pivot from host responses for fingerprints and hashes (e.g., JARM, certificate hash, banner and other header hashes)
-   **Bulk IOC Processing**: Ability to analyze a list of indicators in a single operation.
-   **CSV Export**: Foundational capability to export collected data.

---

### 🚀 **Future Milestones**

This is where IOCTopus is headed next with development. The program is organized into two primary "modes" of operation.

#### **Phase 1: IOC Search Mode Enhancements**

The immediate focus is on enriching the existing IOC analysis capabilities.

##### **Next Priority: Validin Deep Intelligence Integration**
Expand Validin capabilities to provide comprehensive historical and contextual intelligence:

**Domain Intelligence**:
-   **Domain DNS History**: Track historical DNS records for domains over time
-   **Domain OSINT Context**: Gather open-source intelligence context for domains
-   **Domain OSINT History**: Historical OSINT data tracking for domains
-   **Domain DNS Extra**: Retrieve additional DNS records (MX, TXT, NS, etc.) for domains
-   **Domain Registration History**: Track WHOIS/RDAP changes over time
-   **Domain Crawl History**: Historical web crawl data for domains
-   **DNS Reputation Check**: Assess domain reputation based on DNS intelligence

**IP Intelligence**:
-   **IP DNS History**: Find all DNS Records (A or AAAA records) observed for an IP address
-   **IP DNS Extra**: Find observed extra DNS Records for an IP (HTTPS_FOR, SRV_TARGET_FOR associations)
-   **IP OSINT History**: Historical OSINT data for IP addresses
-   **IP OSINT Context**: Current OSINT context for IP addresses
-   **IP Reputation Check**: Assess IP reputation based on multiple factors
-   **IP Crawl History**: Historical crawl data associated with IP addresses

##### **Additional Enhancements**:
-   **Revise Exporting Capabilities**: Overhaul the CSV export feature to produce more structured, actionable reports with prettier formatting and customizable output.
-   **Integrate Criminal IP API**: Add another source of IP and domain intelligence, providing a more complete picture of network indicators.
-   **Integrate Sandbox APIs**:
   -   **CrowdStrike Falcon Sandbox**
   -   **Recorded Future Tria.ge**
-   **Integrate abuse.ch telemetry**

#### **Phase 2: Infrastructure Hunting Mode**

This major new feature will transform IOCTopus from a reactive tool to a proactive discovery engine. The goal is to allow researchers to hunt for adversary infrastructure at scale.

##### **Validin String Pivot Capabilities**:
-   **String Pivots**: Find pivots from host responses for string types (e.g., title, server headers, etc.)
-   **String DNS History**: Retrieve domains that provided responses with specific strings (including special characters)
-   **String Registration History**: View historic WHOIS/RDAP records containing specific strings
-   **Field-Specific Registration Pivoting**: Search registration records by specific fields:
   - Contact Information (Admin, Tech, Billing, Registrant): Names, emails, phones, addresses
   - Registrar Information: Registrar names, emails, addresses
   - Temporal Data: Registration, expiration, change, transfer times
   - Organization Data: Company names, tax IDs, contact types
   - Location Data: Cities, states, countries, postal codes

##### **Core Infrastructure Hunting Features**:
-   **Unified Query Language**: Develop a simplified, powerful query syntax that translates a single search into the native languages of multiple internet asset repositories.
-   **Core Asset API Integrations**:
   -   Criminal IP
   -   Censys
   -   FOFA
   -   Shodan
-   **Data Correlation Engine**: Intelligently link results from asset queries back to IOCs for deeper context and discovery.
-   **Infrastructure Fingerprinting**: Build behavioral profiles of adversary infrastructure based on common patterns and characteristics.
-   **Real-time Infrastructure Monitoring**: Track changes and new appearances of infrastructure matching specific profiles.