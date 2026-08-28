# WiFiRisk: A Lightweight Security Assessment Framework for Low-Cost Wi-Fi Repeaters

A safe, modular and research-oriented Python command-line assessment framework designed to evaluate, threat-model and benchmark the security posture of low-cost Wi-Fi repeaters and consumer IoT networking devices.

---

## Academic Project Context

- **Student Name:** W.M.D.C.D.S Weerakoon
- **Student ID:** 11161
- **Faculty:** Faculty of Computer Science and Engineering, KIU
- **Module:** COM4901 (Final Year Individual Research Project)
- **Project Title:** Security Assessment of Low-Cost Wi-Fi Repeaters: A Study of Consumer Devices Available in Sri Lanka

---

## Table of Contents

1. [Framework Overview](#framework-overview)
2. [Key Capabilities & Features](#key-capabilities--features)
3. [System Architecture](#system-architecture)
4. [Installation & Setup](#installation--setup)
5. [Step-by-Step User Guidance](#step-by-step-user-guidance)
6. [Interactive Menu Reference (20 Options)](#interactive-menu-reference)
7. [Headless CLI Subcommands](#headless-cli-subcommands)
8. [Scoring Engine & Mathematical Formulation](#scoring-engine--mathematical-formulation)
9. [Threat Modeling & Vulnerability Matrix](#threat-modeling--vulnerability-matrix)
10. [MITRE CWE Threat Intelligence & Live Querying](#mitre-cwe-threat-intelligence--live-querying)
11. [Defensive Hardening Guidelines for Manufacturers](#defensive-hardening-guidelines-for-manufacturers)
12. [Directory Structure](#directory-structure)

---

## Framework Overview

Low-cost Wi-Fi repeaters (typically retailing between LKR 2,000 and 3,500 in Sri Lankan e-commerce marketplaces like Daraz) frequently suffer from critical security vulnerabilities. These include exposed plaintext management services (HTTP, Telnet), hardcoded default credentials in client HTML, passwordless login portals, vulnerable embedded DNS resolvers and absent vendor firmware update channels. 

**WiFiRisk** provides an automated, non-destructive security auditing framework tailored specifically for evaluating consumer repeaters. It audits live devices across network, DNS, web and firmware dimensions, records immutable finding evidence, computes an objective **100-point security deduction score**, evaluates the economic **Price-to-Security Ratio (PSR)** and generates multi-format academic research reports in **Microsoft Word (`.docx`)**, **Markdown (`.md`)** and **Plain Text (`.txt`)**.

---

## Key Capabilities & Features

1. **Dual Scanning Modes:**
   - **Quick Live Vulnerability Check (Option 1):** Fast, standalone live network audit probing open ports, DNS resolver responses and web management interfaces without database overhead.
   - **Full In-Depth Assessment (Option 2):** Comprehensive multi-layer evaluation executing network discovery, DNS checks, web audits, firmware scraping, static binary inspection, 100-point scoring and report export.

2. **Device-Isolated Findings & Knowledge Grid Matrix:**
   - Every discovered vulnerability is strictly keyed and isolated by `device_id` and `assessment_id`.
   - The **Show Security Findings** screen displays a structured **Knowledge Grid Matrix** grouping findings by device name and scope in Column 1 and discovered technical weaknesses in Column 2.

3. **Persistent Port Intelligence Correlation:**
   - Findings and open-port evaluations persist permanently in `data/findings.json`.
   - When scanning subsequent devices that expose matching ports, the framework leverages this persistent knowledge base to dig deeper into attack vectors and mitigations.

4. **Live & Offline MITRE CWE Threat Intelligence:**
   - Automatically maps technical evidence to formal **MITRE CWE** taxonomies (e.g. CWE-319, CWE-259, CWE-798, CWE-306, CWE-345, CWE-489).
   - Provides on-demand live lookups against `cwe.mitre.org` with clear pre-flight internet connection notices and automatic offline caching.

5. **Safe Firmware Analysis Engine:**
   - **Path A (Online Discovery):** Queries public search engines and vendor repositories to assess firmware availability and update transparency.
   - **Path B (Static Binary Analysis):** Inspects firmware binaries (`.bin`, `.trx`, `.img`, `.chk`), computes cryptographic hashes (SHA-256, MD5), detects embedded services (`telnetd`, `httpd`, `dnsmasq`), extracts hardcoded strings and checks signatures without flashing or executing untrusted code.

6. **Economic Security Value Model:**
   - Formulates the **Price-to-Security Ratio (PSR)** comparing device security quality against market price relative to a baseline premium device (LKR 15,000).

---

## System Architecture

```text
                                  +-----------------------+
                                  |    WiFiRisk CLI UI    |
                                  |    (Typer & Rich)     |
                                  +-----------+-----------+
                                              |
                   +--------------------------+--------------------------+
                   |                          |                          |
        +----------v----------+    +----------v----------+    +----------v----------+
        |   Quick Live Scan   |    |  Full Assessment    |    |  Modular Scanners   |
        | (quick_scan_service)|    |  (runner_service)   |    |  (Options 5 - 9)    |
        +----------+----------+    +----------+----------+    +----------+----------+
                   |                          |                          |
                   +--------------------------+--------------------------+
                                              |
                      +-----------------------+-----------------------+
                      |                       |                       |
           +----------v----------+ +----------v----------+ +----------v----------+
           |  Firmware Service   | |   Scoring Engine    | |   Report Service    |
           | (Online & Static)   | |  (100-Point & PSR)  | |  (MD, TXT, DOCX)    |
           +---------------------+ +---------------------+ +---------------------+
                      |                       |                       |
           +----------v----------+ +----------v----------+ +----------v----------+
           | CWE Intelligence    | |  Assessment Service | |   Device Service    |
           | (MITRE Live/Offline)| | (Session LifeCycle) | | (Catalog & Compare) |
           +---------------------+ +---------------------+ +---------------------+
                                              |
                                   +----------v----------+
                                   |  Data Layer & Logs  |
                                   | (JSON / Evidence)   |
                                   +---------------------+
```

---

## Installation & Setup

### Prerequisites
- **Python 3.10, 3.11, 3.12, or 3.13** installed on your system.
- Optional: `nmap` installed and added to system `PATH` for advanced port service banner detection.

### Installation on Windows (PowerShell)

```powershell
# 1. Open PowerShell and navigate to the project root directory
cd C:\path\to\wifi-risk-cli

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Installation on Linux / macOS (Terminal)

```bash
# 1. Open Terminal and navigate to the project root directory
cd /path/to/wifi-risk-cli

# 2. Create a virtual environment
python3 -m venv .venv

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step-by-Step User Guidance

### 1. Launching the Interactive Console
Once installed and activated, launch the interactive user interface:
```powershell
python -m wifi_risk
```

---

### 2. Workflow A: Running a Quick Vulnerability Check (Option 1)
Use this option when you want a fast, safe snapshot of a repeater without saving data to an assessment session.
1. Select Option `1` from the main menu.
2. Select your active network adapter or enter the target repeater gateway IP (e.g. `192.168.11.1` or `10.11.159.7`).
3. The real-time progress bar will scan ports, evaluate DNS responses and probe the web management portal.
4. Review the **Security Alerts & Observations Table**.
5. Choose `1..N` to inspect threat scenarios, `A` to view all finding panels, `Q` to query MITRE CWE intelligence online, or `0` to return to the menu.

---

### 3. Workflow B: Running a Full In-Depth Assessment (Option 2)
Use this option for academic evaluation, scoring, Price-to-Security Ratio benchmarking and multi-format report generation.
1. Select Option `2` from the main menu.
2. The wizard presents your options:
   - Create a new assessment session.
   - Run tests for an existing assessment session.
3. Enter device metadata:
   - **Device Identifier:** (e.g. `WR-001`, `Generic-N300`, or `Target-10.11.159.7`).
   - **Retail Price in LKR:** (e.g. `2500` — required for PSR calculation).
   - **Target IP Address:** (e.g. `192.168.11.1`).
   - **Firmware Binary (Optional):** Provide path to local firmware file (e.g. `firmware_samples/wr001_sample_firmware.bin`) for static inspection.
4. The system executes all 5 assessment modules with live animated progress bars:
   - **Layer 1: Network & Port Exposure Discovery**
   - **Layer 2: DNS Resolver & Setup Domain Checks**
   - **Layer 3: Web Management & Authentication Checks**
   - **Layer 4: Online Firmware Update Discovery (Path A)**
   - **Layer 5: Safe Firmware Binary Static Analysis (Path B)**
5. View the final **100-point security deduction breakdown**, **Risk Tier** and **Price-to-Security Ratio (PSR)**.
6. The system prompts to automatically export the complete report in **Word (.docx)**, **Markdown (.md)** and **Plain Text (.txt)** into the `reports/` folder.

---

### 4. Workflow C: Inspecting Stored Security Findings (Option 10)
1. Select Option `10` from the main menu.
2. Choose your query mode:
   - `1` : View findings by specific Assessment ID (e.g. `ASM-001`).
   - `2` : View findings by specific Device ID (e.g. `WR-001`).
   - `3` : View the complete **Knowledge Grid Matrix** across all audited devices.
3. In the Grid Matrix:
   - **Column 1:** Shows the device name, model, finding counts and severity badges.
   - **Column 2:** Lists all confirmed findings with Finding ID, Title, affected layer and mapped CWE.
4. Select `1..N` to open the full technical breakdown panel with impact, evidence and manufacturer remediation steps.

---

### 5. Workflow D: Calculating Scores & PSR (Option 11)
1. Select Option `11` from the main menu.
2. Select an assessment session from the listed options or enter a Device ID.
3. If no price is recorded, the system prompts for the retail purchase price (LKR).
4. The scoring engine calculates:
   - Severity deductions from base 100 points (-12 High, -8 Medium, -5 Low-Med, -3 Low).
   - Risk classification (`Low`, `Medium`, `High`, `Critical`).
   - Economic **Price-to-Security Ratio (PSR)** formula.
   - Tailored deployment recommendation.

---

### 6. Workflow E: Exporting Academic Reports (Option 12)
1. Select Option `12` from the main menu.
2. Select the Assessment ID to export.
3. Choose the export format:
   - `1` : Microsoft Word (`.docx`)
   - `2` : Markdown (`.md`)
   - `3` : Plain Text (`.txt`)
   - `4` : All Formats Simultaneously
4. The generated reports are saved in `reports/` with executive summaries, scoring matrices, evidence logs and manufacturer hardening checklists.

---

### 7. Workflow F: Querying MITRE CWE Threat Intelligence (Option 20)
1. Select Option `20` from the main menu.
2. Choose from:
   - `1` : Lookup CWE Definition by ID (e.g. `319` or `CWE-798`).
   - `2` : Search Local Catalog by Keyword (e.g. `password`, `telnet`, `dns`).
   - `3` : Synchronize Local Knowledge Base with MITRE Online.
3. If a queried CWE is not in the local database, the system alerts you that internet access is needed, connects to `cwe.mitre.org`, extracts the live definition and saves it locally for future offline availability.

---

## Interactive Menu Reference

| Option # | Feature Name | Description |
| :---: | :--- | :--- |
| **1** | **Quick Vulnerability Check** | Fast live scan of target IP gateway detecting open ports, DNS responses and HTTP status with real-time percentage and interactive vulnerability exploration. |
| **2** | **Full In-Depth Assessment** | Comprehensive multi-layer evaluation to analyze price-to-security ratio, execute network/DNS/web/firmware audits, compute score and export reports. |
| **3** | **Create New Assessment Session** | Manually initialize an assessment session record with a custom device ID, price and target IP. |
| **4** | **List & Manage Assessments** | Display recorded audit sessions, view full breakdowns, update session metadata, delete specific assessments or clear all records with confirmation safeguards. |
| **5** | **Run Network Discovery** | Execute standalone TCP socket scans or import Nmap text outputs to audit exposed management ports. |
| **6** | **Run DNS Checks** | Test setup-domain resolution, evaluate DNS resolver responses and check for upstream query leakage. |
| **7** | **Run Web Interface Checks** | Fetch router login HTML, analyze hidden credentials, inspect cookie security flags and audit session handling. |
| **8** | **Online Firmware Discovery (Path A)** | Scrape search indexes and vendor repositories to assess firmware availability and update transparency. |
| **9** | **Firmware Static Analysis (Path B)** | Safely inspect binary firmware images for hashes, embedded daemons and hardcoded credential strings. |
| **10** | **Show Findings** | Review all discovered security vulnerabilities in a clean Knowledge Grid Matrix grouped by device. |
| **11** | **Calculate Score & Recommendation** | Run the 100-point security deduction formula and compute the Price-to-Security Ratio (PSR). |
| **12** | **Export Assessment Report** | Export complete academic audit reports in Markdown (`.md`), Plain Text (`.txt`) and Microsoft Word (`.docx`). |
| **13** | **Select & View Network Interfaces** | List active network adapters, IP subnets and auto-detected default gateways. |
| **14** | **List Devices** | View cataloged repeater models and baseline comparison devices in the database. |
| **15** | **Search Device** | Search the device catalog by brand, model, MAC vendor or keyword. |
| **16** | **Show Device Details** | View technical specifications, purchase price and recorded vulnerabilities for a selected device. |
| **17** | **Compare Devices** | Perform side-by-side comparative analysis of two repeaters across price, score and vulnerabilities. |
| **18** | **Recommend Device by Budget** | Filter and rank repeaters based on maximum budget (LKR) sorted by security score. |
| **19** | **Help & Reference** | In-system interactive user guide explaining testing workflows, formulas and troubleshooting. |
| **20** | **Query Online CWE & Threat Intelligence** | Query official MITRE taxonomy definitions, search vulnerabilities by keyword and sync live updates over the internet. |
| **0** | **Exit** | Terminate the application cleanly. |

---

## Headless CLI Subcommands

WiFiRisk can also be executed directly from the terminal or automated scripts:

### 1. Run Full Assessment Headless
```powershell
python -m wifi_risk run --target-ip 192.168.11.1 --device-id WR-001 --price 2500 --brand Urant --model "Wi-Fi Repeater"
```

### 2. Export Assessment Reports
```powershell
python -m wifi_risk export --assessment-id ASM-001 --format all --output-dir reports
```

### 3. Calculate Security Score & PSR
```powershell
python -m wifi_risk score --device-id WR-001 --price 2500
```

### 4. Query MITRE CWE Threat Intelligence
```powershell
python -m wifi_risk cwe 319
python -m wifi_risk cwe 798 --online
```

### 5. List Network Interfaces & Gateways
```powershell
python -m wifi_risk interfaces
```

### 6. List Cataloged Devices
```powershell
python -m wifi_risk devices
```

---

## Scoring Engine & Mathematical Formulation

### 1. 100-Point Security Score Calculation
The base security score begins at 100 points. Points are deducted based on the severity of each verified finding:

$$\text{Final Score} = \max\left(0, 100 - \sum \text{Severity Deductions}\right)$$

| Severity Tier | Points Deducted per Finding | Typical Finding Example |
| :--- | :---: | :--- |
| **Critical** | -15 pts | Remote unauthenticated root command execution |
| **High** | -12 pts | Exposed Telnet (23/TCP), hardcoded credentials in HTML |
| **Medium** | -8 pts | Unencrypted HTTP management (80/TCP), exposed FTP (21/TCP) |
| **Low-Medium** | -5 pts | Exposed DNS resolver, missing logout button |
| **Low** | -3 pts | Verbose server headers, minor cookie flag omissions |
| **Informational** | -1 pt | Service banners, generic configuration notices |

### 2. Risk Level Classification

| Final Score | Risk Tier | Evaluation Guidance |
| :---: | :---: | :--- |
| **85 – 100** | **Low Risk** | Strong configuration, minimal exposure, safe for deployment. |
| **65 – 84** | **Medium Risk** | Moderate vulnerabilities, requires configuration hardening. |
| **40 – 64** | **High Risk** | Severe exposures (e.g. plaintext services), isolated use only. |
| **0 – 39** | **Critical Risk** | Critical flaws (e.g. hardcoded root shell), do not deploy. |

### 3. Price-to-Security Ratio (PSR)
The Price-to-Security Ratio quantifies the security value delivered per unit cost relative to an enterprise baseline device (priced at LKR 15,000 with a score of 100):

$$\text{PSR} = \frac{\text{Device Security Score} / 100}{\text{Device Price (LKR)} / 15000}$$

- **High PSR (> 3.0):** High security score at low cost (excellent economic value).
- **Moderate PSR (1.0 - 3.0):** Fair security value proportional to cost.
- **Poor PSR (< 1.0):** Device is overpriced for the level of security it delivers.

---

## Threat Modeling & Vulnerability Matrix

| Discovered Service / Port | Weakness Standard | Threat & Lab Attack Scenario | Impact | Defensive Hardening Coverage |
| :--- | :--- | :--- | :--- | :--- |
| **Unencrypted HTTP (80/TCP)** | CWE-319, CWE-352, CWE-306 | Man-in-the-Middle credential sniffing over shared Wi-Fi and Cross-Site Request Forgery (CSRF) router reconfiguration. | Plaintext credential capture, unauthorized DNS/Wi-Fi configuration changes. | Enforce HTTPS (TLS 1.2/1.3), enable HSTS, implement anti-CSRF tokens and set `SameSite=Strict` cookie attributes. |
| **Exposed DNS Resolver (53/TCP)** | CWE-345, CWE-400, CVE-2020-25681 (DNSpooq) | DNS Cache Poisoning and forged DNS response flooding redirecting client traffic to phishing servers. | Domain hijacking, local traffic interception and phishing redirection. | Upgrade `dnsmasq` to >= 2.83, bind DNS daemon strictly to internal LAN and enable DNSSEC verification. |
| **Open Telnet Service (23/TCP)** | CWE-319, CWE-798, CWE-307 | Automated dictionary attacks (Mirai-style botnets) and cleartext remote shell session sniffing. | Remote root shell compromise, botnet recruitment and persistent backdoors. | Disable Telnet in production firmware, replace with SSH public-key authentication and block port 23 in iptables. |
| **Hardcoded Admin Credentials** | CWE-798, CWE-200 | Unauthenticated users inspect webpage HTML source code or DOM tree to extract admin credentials. | Zero-touch administrative takeover without cracking or brute-forcing. | Remove hardcoded credentials from templates, generate unique per-unit factory passwords and enforce setup wizards. |
| **Absent Firmware Updates** | CWE-1059, CWE-1277 | Device runs outdated firmware with unpatched vulnerabilities with no vendor download archive. | Permanent exposure to public CVE exploits with no remediation path. | Establish public firmware support portals, publish cryptographic checksums and implement signed firmware updates. |

---

## MITRE CWE Threat Intelligence & Live Querying

WiFiRisk features a dedicated intelligence service that bridges discovered technical evidence with the formal **MITRE CWE** taxonomy. Users can query definitions by ID or perform keyword searches across the local database, with the system providing on-demand internet synchronization to fetch up-to-date threat intel as needed.

---

## Defensive Hardening Guidelines for Manufacturers

1. **Eliminate Insecure Defaults:**
   - Remove hardcoded credentials (`admin`/`admin`, `root`/`root`).
   - Assign a unique, cryptographically random password to each physical device printed on the physical device label (complying with the **UK PSTI Act 2024** and **ETSI EN 303 645** standards).
2. **Mandate Encryption by Default:**
   - Provide HTTPS management portals by embedding lightweight cryptographic libraries (such as **mbedTLS** or **WolfSSL**).
   - Disable cleartext management protocols (Telnet, HTTP, FTP) by default.
3. **Isolate Network Listeners:**
   - Bind administration services strictly to internal wireless/Ethernet interfaces.
   - Prevent management portal exposure to upstream WAN interfaces.
4. **Maintain Embedded Dependencies:**
   - Keep open-source daemons (such as `dnsmasq`, `busybox`, `uhttpd`) updated to current stable releases to avoid known CVE advisories.
5. **Implement Secure Firmware Lifecycle:**
   - Provide an official firmware update repository with cryptographic signature validation to prevent malicious firmware flashing.

---

## Directory Structure

```text
wifi-risk-cli/
├── README.md                       # Comprehensive framework documentation and user guide
├── requirements.txt                # Python package dependencies
├── .gitignore                      # Environment, IDE and bytecode exclusions
├── data/
│   ├── assessments.json            # Assessment session database
│   ├── devices.json                # Evaluated repeaters and benchmark devices
│   ├── findings.json               # Central knowledge base of security findings
│   ├── cwe_catalog.json            # Local MITRE CWE taxonomy database
│   └── evidence/                   # Raw scan outputs and module evidence JSON files
├── firmware_samples/               # Sample firmware binaries for static analysis
├── reports/                        # Exported Markdown, TXT and DOCX audit reports
└── wifi_risk/
    ├── __init__.py                 # Package initializer
    ├── __main__.py                 # Entry point for python -m wifi_risk
    ├── cli.py                      # Interactive console UI, screens and subcommands
    ├── models/                     # Data models (Assessment, Device, Finding)
    ├── services/                   # Assessment business logic
    │   ├── assessment_service.py   # Assessment session lifecycle and persistence
    │   ├── cwe_intelligence_service.py # MITRE CWE online/offline lookup and sync
    │   ├── device_service.py       # Device database querying and comparison
    │   ├── dns_service.py          # DNS resolution and setup domain redirection
    │   ├── finding_service.py      # Findings CRUD, importing and grid filtering
    │   ├── firmware_service.py     # Online discovery and static binary analysis
    │   ├── network_service.py      # Safe TCP socket scan and Nmap parser
    │   ├── quick_scan_service.py   # Standalone quick scan and alert evaluator
    │   ├── report_service.py       # Multi-format report exporter (MD, TXT, DOCX)
    │   ├── runner_service.py       # Full assessment pipeline coordinator
    │   ├── scoring_service.py      # 100-point deduction and PSR scoring engine
    │   └── web_service.py          # Web interface HTML and authentication auditor
    └── utils/                      # Helper utilities
        ├── command_runner.py       # Safe subprocess executor
        ├── file_loader.py          # JSON and file I/O helpers
        └── network_detector.py     # Adapter and gateway detection utility
```