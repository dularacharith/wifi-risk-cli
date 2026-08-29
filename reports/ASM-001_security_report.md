# WiFiRisk Security Assessment & Threat Modeling Report

## Academic Project Context
- **Project Title:** WiFiRisk: A Lightweight Security Assessment Framework for Low-Cost Wi-Fi Repeaters
- **Student Name:** W.M.D.C.D.S Weerakoon
- **Student ID:** 11161
- **Faculty:** Faculty of Computer Science and Engineering, KIU
- **Module:** COM4901 (Final Year Individual Research Project)

---

## 1. Assessment Overview
- **Assessment ID:** `ASM-001`
- **Assessment Status:** Created
- **Date Generated:** 2026-08-29 14:23:05
- **Target Gateway IP:** `10.11.159.7`
- **Device Identifier:** `Target-10.11.159.7`
- **Device Brand / Model:** Generic Wi-Fi Repeater
- **Firmware Version:** `Unknown`
- **Purchase Price:** LKR 20000
- **Assessment Notes:** Session via wlp0s20f3

## 2. Executive Summary & Security Scorecard
- **Security Score:** **100 / 100**
- **Base Points:** 100 (Total Deductions: -0 points)
- **Risk Level:** **Low**
- **Price-to-Security Ratio (PSR):** **0.75** (Baseline Premium: LKR 15,000)
- **Recommendation Category:** **Recommended**

> **Guidance:** The device demonstrates acceptable baseline security with low observed risk.
>
> **Price Evaluation:** Price: LKR 20000 with PSR score 0.75.

### Score Deductions Breakdown
| Finding ID | Severity | Points Deducted | Title |
| :--- | :---: | :---: | :--- |

## 3. Detailed Vulnerability Findings & Threat Modeling
*No security vulnerabilities or exposures were detected on the target device.*
## 4. Comprehensive Device Hardening & Defense Plan
1. Change default administrator passwords immediately upon deployment.
2. Disable unencrypted services such as Telnet and HTTP where possible.
3. Isolate repeater devices on a dedicated guest or test VLAN.
4. Verify firmware update availability from verified vendor sources.
