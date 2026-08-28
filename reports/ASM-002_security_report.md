# WiFiRisk Security Assessment & Threat Modeling Report

## Academic Project Context
- **Project Title:** WiFiRisk: A Lightweight Security Assessment Framework for Low-Cost Wi-Fi Repeaters
- **Student Name:** W.M.D.C.D.S Weerakoon
- **Student ID:** 11161
- **Faculty:** Faculty of Computer Science and Engineering, KIU
- **Module:** COM4901 (Final Year Individual Research Project)

---

## 1. Assessment Overview
- **Assessment ID:** `ASM-002`
- **Assessment Status:** In Progress
- **Date Generated:** 2026-08-28 17:50:20
- **Target Gateway IP:** `192.168.26.1`
- **Device Identifier:** `Target-192.168.26.1`
- **Device Brand / Model:** Generic Wi-Fi Repeater
- **Firmware Version:** `Unknown`
- **Purchase Price:** LKR 2500
- **Assessment Notes:** Session via vmnet1

## 2. Executive Summary & Security Scorecard
- **Security Score:** **95 / 100**
- **Base Points:** 100 (Total Deductions: -5 points)
- **Risk Level:** **Low**
- **Price-to-Security Ratio (PSR):** **5.7** (Baseline Premium: LKR 15,000)
- **Recommendation Category:** **Recommended**

> **Guidance:** The device demonstrates acceptable baseline security with low observed risk.
>
> **Price Evaluation:** Price: LKR 2500 with PSR score 5.7.

### Score Deductions Breakdown
| Finding ID | Severity | Points Deducted | Title |
| :--- | :---: | :---: | :--- |
| `T1-F05` | Low-Medium | -5 | DNS resolver exposed on management interface |

## 3. Detailed Vulnerability Findings & Threat Modeling
### 1. [T1-F05] DNS resolver exposed on management interface
- **Severity:** Low-Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-400 (Resource Amplification)
- **Category:** Network-Level Exposure / DNS Behavior
- **Module:** Network Discovery
- **Threat Modeling & Attack Vector:** In a threat environment, an outdated or misconfigured DNS daemon (such as legacy dnsmasq versions) can be targeted for DNS Cache Poisoning (DNSpooq series) or DNS Spoofing attacks. An attacker can forge DNS responses to poison the repeater's cache, redirecting all connected users from legitimate domains (such as banking or social media) to malicious phishing servers.
- **Security Impact:** The device runs an active DNS resolver which may redirect setup queries or expose internal DNS resolution.
- **Recommended Mitigation:** Restrict DNS exposure to required client interfaces only and validate redirect behavior.
- **Hardening Action Steps:**
  - 1. Upgrade dnsmasq to version 2.83 or later to mitigate DNSpooq vulnerability advisories (CVE-2020-25681 through CVE-2020-25687).
  - 2. Configure the DNS server to listen exclusively on the internal LAN interface (bind-interfaces).
  - 3. Enable source port randomization and DNSSEC query verification in dnsmasq configuration.

## 4. Comprehensive Device Hardening & Defense Plan
1. Change default administrator passwords immediately upon deployment.
2. Disable unencrypted services such as Telnet and HTTP where possible.
3. Isolate repeater devices on a dedicated guest or test VLAN.
4. Verify firmware update availability from verified vendor sources.
