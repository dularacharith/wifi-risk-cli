# WiFiRisk: Security Assessment Framework for Low-Cost Wi-Fi Repeaters

A safe, modular and research-oriented Python command-line assessment framework designed to evaluate, threat-model and benchmark the security posture of low-cost Wi-Fi repeaters and consumer IoT networking devices.

---

## Academic Project Context

- **Student Name:** W.M.D.C.D.S Weerakoon
- **Student ID:** 11161
- **Faculty:** Faculty of Computer Science and Engineering, KIU
- **Module:** COM4901 (Final Year Individual Research Project)
- **Project Title:** Security Assessment of Low-Cost Wi-Fi Repeaters: A Study of Consumer Devices Available in Sri Lanka

---

## About the Framework

Low-cost Wi-Fi repeaters (typically retailing between LKR 2,000 and 3,500 in consumer e-commerce markets) frequently suffer from critical security flaws, including unencrypted management services (HTTP, Telnet), hardcoded administrator credentials in client HTML, passwordless login portals, vulnerable embedded DNS resolvers and absent vendor firmware update channels.

**WiFiRisk** automates non-destructive security audits for consumer Wi-Fi repeaters across network, DNS, web and firmware layers. It computes an objective **100-point security deduction score**, evaluates the economic **Price-to-Security Ratio (PSR)** and generates multi-format academic audit reports in **Microsoft Word (`.docx`)**, **Markdown (`.md`)** and **Plain Text (`.txt`)**.

---

## Key Features

- **Dual Scanning Modes:** Standalone quick live scan (Option 1) and comprehensive full multi-layer assessment (Option 2).
- **Device-Isolated Findings Grid Matrix:** Strict separation of vulnerabilities per device, displayed in a clean two-column grid (Device Name in Column 1, Discovered Findings in Column 2).
- **Persistent Port Intelligence:** Stored findings and port behaviors persist in `data/findings.json` to help analyze matching ports across subsequent devices.
- **MITRE CWE Threat Intelligence:** Dynamic mapping of findings to official MITRE CWE taxonomies with live online fetching from `cwe.mitre.org` and automatic local caching.
- **Safe Dual-Path Firmware Analysis:** Online vendor update discovery (Path A) and static firmware binary string/hash inspection (Path B).
- **Multi-Format Report Exporter:** Automated generation of Word (.docx), Markdown (.md) and Plain Text (.txt) reports.

---

## Prerequisites & Installation

### 1. Python Environment
Ensure **Python 3.10+** (3.10, 3.11, 3.12, or 3.13) is installed.

### 2. Installing Nmap & Adding to PATH (Optional but Recommended)
Nmap is used by WiFiRisk for enhanced service banner detection. If Nmap is not installed, the tool automatically falls back to native Python socket scanning.

#### Windows Setup:
1. Download the latest Nmap setup installer (`nmap-<version>-setup.exe`) from [https://nmap.org/download.html](https://nmap.org/download.html).
2. Run the installer and ensure the **Npcap** component is checked.
3. If Nmap was not automatically added to your system `PATH`:
   - Open **PowerShell as Administrator** and add Nmap to your system Path:
     ```powershell
     [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files (x86)\Nmap", [EnvironmentVariableTarget]::Machine)
     ```
   - Alternatively, open **Windows Settings** -> **System** -> **About** -> **Advanced system settings** -> **Environment Variables**, select `Path` under *System variables*, click *Edit*, and add `C:\Program Files (x86)\Nmap` (or your custom install directory).
4. Verify installation in a new PowerShell window:
   ```powershell
   nmap --version
   ```

#### Linux Setup (Debian / Ubuntu / Kali):
```bash
sudo apt update && sudo apt install nmap -y
nmap --version
```

#### macOS Setup:
```bash
brew install nmap
nmap --version
```

---

### 3. Project Installation

#### Windows (PowerShell):
```powershell
# 1. Clone or navigate to the project directory
cd C:\path\to\wifi-risk-cli

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Linux / macOS:
```bash
# 1. Clone or navigate to the project directory
cd /path/to/wifi-risk-cli

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## How to Run & Use the System

Launch the interactive console application:
```powershell
python -m wifi_risk
```

### Core Workflows

1. **Quick Live Vulnerability Check (Option 1):**
   - Enter your target repeater gateway IP (e.g. `192.168.11.1` or `10.11.159.7`).
   - The tool performs a fast live probe across open ports, DNS resolver behavior and web interface reachability.
   - Displays real-time progress, followed by a security alert table and interactive drill-down options.

2. **Full In-Depth Assessment (Option 2):**
   - Initializes an assessment session with Device ID, retail purchase price (LKR) and target IP.
   - Executes Network Discovery, DNS Checks, Web Interface Inspection and Firmware Analysis.
   - Computes the 100-point security deduction score, determines the risk level and evaluates the Price-to-Security Ratio (PSR).
   - Prompts to automatically export the complete report in Word (`.docx`), Markdown (`.md`) and Plain Text (`.txt`).

3. **View Security Findings Matrix (Option 10):**
   - Displays confirmed vulnerabilities in a clean **Knowledge Grid Matrix** with Device Name in Column 1 and Discovered Vulnerabilities (Severity, Finding ID, Title, Layer, CWE, Impact) in Column 2.
   - Allows on-demand drill-down into threat modeling and mitigation guides for any specific finding.

4. **Calculate Score & PSR (Option 11):**
   - Evaluates recorded findings for a chosen assessment session or device.
   - Enforces price entry to calculate the economic Price-to-Security Ratio.

5. **Export Assessment Reports (Option 12):**
   - Generates formatted audit reports in Microsoft Word, Markdown and Plain Text into the `reports/` folder.

6. **Query MITRE CWE Threat Intelligence (Option 20):**
   - Lookup weakness definitions by CWE ID (e.g. `319`, `CWE-798`) or keyword.
   - If not present in the local database, queries `cwe.mitre.org` live over the internet and caches the result for future offline use.

---

## Interactive Menu Reference

WiFiRisk features a streamlined, categorized interactive console with 8 intuitive top-level modules:

| Option # | Main Menu Category | Sub-Actions & Capabilities Included |
| :---: | :--- | :--- |
| **1** | **Quick Vulnerability Check** | Fast standalone network scan of gateway IP with real-time progress and vulnerability exploration. |
| **2** | **Full In-Depth Assessment** | Complete multi-layer automated evaluation pipeline, 100-point scoring, PSR calculation and report generation. |
| **3** | **Standalone Assessment Modules** | Modular testing suite: Create Session, Port Scan, DNS Checks, Web Checks, Firmware Discovery & Static Analysis. |
| **4** | **View & Manage Assessments** | Categorized assessment viewer (All, Quick Scans, Full Audits, Created), in-place report exporting and synchronized clearing. |
| **5** | **Security Scorecard & Findings** | Discovered Findings Knowledge Grid Matrix grouped by device and 100-point PSR Security Score Calculator. |
| **6** | **Device Catalog & Benchmarking** | List Catalog, Search Models, Device Details, Side-by-Side Comparison Matrix and Budget Recommendations. |
| **7** | **MITRE CWE Threat Intelligence** | Live online MITRE / NVD threat definition lookups, taxonomy search and local catalog synchronization. |
| **8** | **Network Tools & Documentation** | Network adapter interface selection, Gateway IP auto-detection and Help / Methodology Reference Guide. |
| **0** | **Exit** | Terminate the application cleanly. |

---

## Headless CLI Subcommands

WiFiRisk can also be executed directly via command line arguments:

```powershell
# Run full assessment headless
python -m wifi_risk run --target-ip 192.168.11.1 --device-id WR-001 --price 2500

# Export assessment reports
python -m wifi_risk export --assessment-id ASM-001 --format all --output-dir reports

# Export complete research test dataset & audit log (for supervisors/reviewers)
python -m wifi_risk export-dataset --format all --output-dir reports

# Calculate security score & PSR
python -m wifi_risk score --device-id WR-001 --price 2500

# Query MITRE CWE threat intelligence
python -m wifi_risk cwe 319
python -m wifi_risk cwe 798 --online

# List network adapters and cataloged devices
python -m wifi_risk interfaces
python -m wifi_risk devices
```

---

## Scoring Model & Mathematical Formulations

### 1. 100-Point Security Score
The security score begins at 100 points and deducts points based on verified findings:

$$\text{Final Score} = \max\left(0, 100 - \sum \text{Severity Deductions}\right)$$

| Severity Tier | Points Deducted | Risk Classification |
| :--- | :---: | :--- |
| **Critical** | -15 pts | **85 – 100:** Low Risk |
| **High** | -12 pts | **65 – 84:** Medium Risk |
| **Medium** | -8 pts | **40 – 64:** High Risk |
| **Low-Medium** | -5 pts | **0 – 39:** Critical Risk |
| **Low** | -3 pts | |
| **Informational** | -1 pt | |

### 2. Price-to-Security Ratio (PSR)
The Price-to-Security Ratio quantifies security value delivered per unit cost relative to a baseline premium device (priced at LKR 15,000 with a score of 100):

$$\text{PSR} = \frac{\text{Device Security Score} / 100}{\text{Device Price (LKR)} / 15000}$$

- **High PSR (> 3.0):** High security quality relative to low cost.
- **Moderate PSR (1.0 – 3.0):** Fair security value proportional to cost.
- **Poor PSR (< 1.0):** Overpriced for the level of security provided.