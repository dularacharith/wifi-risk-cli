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
- **Assessment Status:** In Progress
- **Date Generated:** 2026-08-28 17:50:20
- **Target Gateway IP:** `10.11.159.7`
- **Device Identifier:** `Target-10.11.159.7`
- **Device Brand / Model:** Generic Wi-Fi Repeater
- **Firmware Version:** `Unknown`
- **Purchase Price:** LKR 2500
- **Assessment Notes:** Session via wlp0s20f3

## 2. Executive Summary & Security Scorecard
- **Security Score:** **0 / 100**
- **Base Points:** 100 (Total Deductions: -100 points)
- **Risk Level:** **Critical**
- **Price-to-Security Ratio (PSR):** **0.0** (Baseline Premium: LKR 15,000)
- **Recommendation Category:** **Avoid for sensitive networks**

> **Guidance:** Multiple severe vulnerabilities identified (such as hardcoded credentials or exposed services). Do not connect to banking, work or sensitive corporate networks.
>
> **Price Evaluation:** At LKR 2500 (PSR: 0.0), the device appears affordable, but its low security score (0/100) presents significant risk.

### Score Deductions Breakdown
| Finding ID | Severity | Points Deducted | Title |
| :--- | :---: | :---: | :--- |
| `WR-001-F01` | High | -12 | Telnet service exposed on local and upstream interfaces |
| `WR-001-F02` | High | -12 | Web interface allows login without user-supplied credentials |
| `WR-001-F03` | High | -12 | Default admin credentials exposed in login page HTML |
| `WR-001-F04` | High | -12 | Admin credentials stored in Base64 Authorization cookie |
| `WR-001-F05` | Low-Medium | -5 | DNS resolver exposed on management interface |
| `WR-001-F06` | Medium | -8 | No logout option to terminate admin session |
| `WR-001-F07` | High | -12 | Admin credentials exposed in URL query parameters during login |
| `WR-001-F_HTTP_ADMIN` | Medium | -8 | Web management interface served over unencrypted HTTP |
| `WR-001-F_FW_UNAVAILABLE` | Medium | -8 | Public firmware updates and vendor support unavailable |
| `WR-001-FW_HARDCODED_CREDS` | High | -12 | Hardcoded default administrator credentials in firmware image |
| `WR-001-FW_TELNETD` | High | -12 | Embedded Telnet daemon (telnetd) present in firmware |
| `WR-001-FW_UNSIGNED` | Medium | -8 | Firmware package lacks cryptographic signature verification |
| `D1-F01` | High | -12 | Telnet service exposed on local and upstream interfaces |
| `D1-F_HTTP` | Medium | -8 | Unencrypted HTTP management interface exposed |
| `D1-F_HTTP_ADMIN` | Medium | -8 | Web management interface served over unencrypted HTTP |
| `D1-F03` | High | -12 | Default admin credentials exposed in login page HTML |
| `D1-F04` | High | -12 | Admin credentials stored in Base64 Authorization cookie |
| `D1-F_FW_UNAVAILABLE` | Medium | -8 | Public firmware updates and vendor support unavailable |

## 3. Detailed Vulnerability Findings & Threat Modeling
### 1. [WR-001-F01] Telnet service exposed on local and upstream interfaces
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-319 (Cleartext Transmission) / CWE-259 (Hardcoded Password)
- **Category:** Network-Level Exposure / Insecure Defaults
- **Module:** Network Discovery
- **Observed Technical Evidence:** `Nmap showed 23/tcp open on 192.168.11.1 and also on upstream hotspot-side IPs such as 10.79.151.53 and 10.79.151.163. The service returned Login as:.`
- **Threat Modeling & Attack Vector:** In a threat environment, an attacker connected to the Wi-Fi or upstream network can perform automated dictionary attacks (such as Mirai-style brute force) or sniff cleartext administrative commands and root credentials transmitted across the network.
- **Security Impact:** A local network attacker may reach the Telnet-like login service. If weak or hardcoded credentials exist, this may allow remote administrative or shell access.
- **Recommended Mitigation:** Disable Telnet by default and replace it with SSH only if remote administration is required.
- **Hardening Action Steps:**
  - 1. Remove the telnetd daemon from the device startup scripts (e.g. /etc/init.d/rcS).
  - 2. Block inbound TCP port 23 across all network interfaces using iptables firewall rules.
  - 3. Enforce cryptographic authentication (SSH) and disable default root accounts.

### 2. [WR-001-F02] Web interface allows login without user-supplied credentials
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-306 (Missing Authentication for Critical Function) / CWE-287 (Improper Authentication)
- **Category:** Authentication Security
- **Module:** Web Interface Checks
- **Threat Modeling & Attack Vector:** Any unauthenticated attacker on the local Wi-Fi network can bypass authentication and access the router management portal by simply submitting an empty form or clicking login.
- **Security Impact:** The login page does not require the user to input credentials, allowing anyone on the network to click LOGIN and access the admin dashboard.
- **Recommended Mitigation:** Require users to configure and enter a unique administrator password during initial setup.
- **Hardening Action Steps:**
  - 1. Require a mandatory user-defined administrator password during initial device onboarding.
  - 2. Reject empty password authentication attempts on the backend.
  - 3. Disable bypass authentication routes in web server CGI handlers.

### 3. [WR-001-F03] Default admin credentials exposed in login page HTML
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-798 (Use of Hardcoded Credentials) / CWE-200 (Exposure of Sensitive Information)
- **Category:** Authentication Security / Insecure Defaults
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `index.html contains hidden username value admin and hidden password value admin.`
- **Threat Modeling & Attack Vector:** An attacker inspecting client-side HTML or automated crawlers can immediately harvest default administrative credentials without guessing or brute-forcing.
- **Security Impact:** The login page reveals hidden username and default password values to anyone inspecting the client source.
- **Recommended Mitigation:** Remove hardcoded credentials from client-side HTML.
- **Hardening Action Steps:**
  - 1. Remove all hardcoded default credentials from client-side HTML, JavaScript, and hidden form fields.
  - 2. Authenticate credentials strictly on the server side.
  - 3. Enforce a mandatory setup wizard requiring unique password configuration.

### 4. [WR-001-F04] Admin credentials stored in Base64 Authorization cookie
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-312 (Cleartext Storage of Sensitive Information) / CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)
- **Category:** Session Management
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `Browser storage shows a cookie named Authorization. The cookie value starts with Basic. HttpOnly is false. Secure is false. SameSite is blank or not set. JavaScript creates the cookie using Base64-encoded admin:<password>.`
- **Threat Modeling & Attack Vector:** Because Base64 is trivially reversible and the cookie lacks HttpOnly/Secure flags, any client-side script (XSS) or local network eavesdropper can decode the plaintext admin credentials directly from the cookie header.
- **Security Impact:** The cookie can expose admin credentials because Base64 is not encryption and the cookie is not HttpOnly or Secure.
- **Recommended Mitigation:** Use secure server-side session tokens with HttpOnly, Secure and SameSite attributes.
- **Hardening Action Steps:**
  - 1. Implement cryptographically random session tokens (e.g. 128-bit tokens) stored in server memory.
  - 2. Set 'HttpOnly', 'Secure', and 'SameSite=Strict' flags on all session cookies.
  - 3. Never store credentials or reversible encodings in client cookies.

### 5. [WR-001-F05] DNS resolver exposed on management interface
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

### 6. [WR-001-F06] No logout option to terminate admin session
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-613 (Insufficient Session Expiration)
- **Category:** Session Management
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `After login, status.html shows setup options but there is no visible logout option.`
- **Threat Modeling & Attack Vector:** Without an explicit logout mechanism, administrative sessions remain valid on shared client workstations and mobile browsers, allowing subsequent users to access the router dashboard.
- **Security Impact:** Users cannot explicitly terminate the admin session from the interface, leaving administrative access open indefinitely on shared clients.
- **Recommended Mitigation:** Add a logout function that clears and invalidates the session.
- **Hardening Action Steps:**
  - 1. Provide a visible 'Logout' button on all dashboard navigation menus.
  - 2. Invalidate server-side session tokens upon logout request.
  - 3. Instruct client browsers to clear authentication cookies on session termination.

### 7. [WR-001-F07] Admin credentials exposed in URL query parameters during login
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-598 (Use of GET Request Method with Sensitive Query Strings) / CWE-319 (Cleartext Transmission)
- **Category:** Sensitive Data Exposure
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `Browser address bar showed a login request like http://192.168.11.1/login.htm?CMD=USERLOGIN&username=admin&pcPassword=admin&lang=auto#`
- **Threat Modeling & Attack Vector:** Credentials transmitted in GET query strings are permanently retained in browser history, proxy logs, server access logs, and referrer headers, facilitating passive credential compromise.
- **Security Impact:** Credentials may be stored in browser history, logs, screenshots and network captures.
- **Recommended Mitigation:** Submit credentials using POST over HTTPS and never place passwords in URLs.
- **Hardening Action Steps:**
  - 1. Transmit authentication credentials strictly via HTTP POST requests in the request body over HTTPS.
  - 2. Strip query string parameters on the server side.
  - 3. Prevent GET-based authentication in CGI binaries.

### 8. [WR-001-F_HTTP_ADMIN] Web management interface served over unencrypted HTTP
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-352 (Cross-Site Request Forgery)
- **Category:** Sensitive Data Exposure / Transport Security
- **Module:** Web Interface Checks
- **Threat Modeling & Attack Vector:** An attacker on the same local Wi-Fi or upstream network can capture cleartext HTTP authentication traffic and session tokens via Wi-Fi sniffing or ARP spoofing. Without transport encryption or CSRF tokens, attackers can also forge router reconfiguration requests.
- **Security Impact:** All web interactions, login attempts, and configurations are sent in plaintext and vulnerable to local eavesdropping.
- **Recommended Mitigation:** Configure HTTPS encryption for the web management portal.
- **Hardening Action Steps:**
  - 1. Embed lightweight TLS support (e.g. mbedTLS / WolfSSL) into the embedded web server.
  - 2. Enable automatic redirection from HTTP port 80 to HTTPS port 443 with HSTS headers.
  - 3. Implement unique cryptographic certificates per device.

### 9. [WR-001-F_FW_UNAVAILABLE] Public firmware updates and vendor support unavailable
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-1277 (Firmware Not Updateable) / CWE-1059 (Incomplete Documentation and Support)
- **Category:** Firmware Weaknesses / Lack of Vendor Transparency
- **Module:** Firmware Analysis
- **Observed Technical Evidence:** `Online discovery using queries: "Urant 1.0.1.2-urant-p1R-auto firmware", "1.0.1.2-urant-p1R-auto" firmware, "1.0.1.2-urant-p1R-auto" returned no official vendor firmware repositories or support portals.`
- **Threat Modeling & Attack Vector:** In a threat environment, when zero-day vulnerabilities or public CVEs (e.g. DNSpooq or Mirai exploits) affect embedded daemons, device owners cannot patch or update their repeaters, leaving them permanently vulnerable to automated botnets.
- **Security Impact:** The device manufacturer does not provide an official firmware update repository or public security patches, leaving known vulnerabilities unpatchable.
- **Recommended Mitigation:** Avoid using generic networking hardware that lacks transparent vendor support and ongoing security patch cycles.
- **Hardening Action Steps:**
  - 1. Establish a public, verifiable vendor security advisory portal.
  - 2. Provide cryptographically signed Over-the-Air (OTA) or manual firmware upgrade images.
  - 3. Publish transparent release notes and security vulnerability fixes.

### 10. [WR-001-FW_HARDCODED_CREDS] Hardcoded default administrator credentials in firmware image
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-798 (Use of Hardcoded Credentials) / CWE-259 (Use of Hardcoded Password)
- **Category:** Firmware Static Analysis / Hardcoded Credentials
- **Module:** Firmware Static Analysis
- **Observed Technical Evidence:** `Found credential strings in firmware binary wr001_sample_firmware.bin: Default configuration: username=admin password=admin pcPassword=admin`
- **Threat Modeling & Attack Vector:** An attacker extracting binary strings from the firmware image can identify global default passwords and user accounts, allowing automated unauthorized logins across any deployment of this repeater model.
- **Security Impact:** Static strings embedded inside firmware binaries expose default credentials, facilitating unauthorized administrative access across all identical devices.
- **Recommended Mitigation:** Remove all embedded plaintext default credentials and enforce unique per-device initialization keys.
- **Hardening Action Steps:**
  - 1. Strip all plaintext passwords and default usernames from embedded binaries and /etc/shadow templates.
  - 2. Generate a cryptographically random, unique device key printed on physical device labels.
  - 3. Enforce a mandatory password reset on initial device bootstrap.

### 11. [WR-001-FW_TELNETD] Embedded Telnet daemon (telnetd) present in firmware
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-250 (Execution with Unnecessary Privileges)
- **Category:** Firmware Static Analysis / Insecure Services
- **Module:** Firmware Static Analysis
- **Observed Technical Evidence:** `Found telnetd references and binaries embedded inside firmware wr001_sample_firmware.bin.`
- **Threat Modeling & Attack Vector:** Embedded telnetd binary with startup scripts creates an unencrypted remote root shell. Attackers scanning local Wi-Fi or IoT subnets can brute-force Telnet or sniff root commands in cleartext.
- **Security Impact:** The inclusion of telnetd enables unencrypted command-line management on exposed network ports.
- **Recommended Mitigation:** Remove telnetd from production firmware builds or disable its daemon startup by default.
- **Hardening Action Steps:**
  - 1. Exclude the telnetd package from the busybox/OpenWrt build configuration.
  - 2. Remove telnetd invocations from /etc/init.d/rcS startup scripts.
  - 3. Implement secure SSH (Dropbear) with key-based authentication for diagnostic builds.

### 12. [WR-001-FW_UNSIGNED] Firmware package lacks cryptographic signature verification
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-347 (Improper Verification of Cryptographic Signature) / CWE-494 (Download of Code Without Integrity Check)
- **Category:** Firmware Static Analysis / Integrity Validation
- **Module:** Firmware Static Analysis
- **Observed Technical Evidence:** `Firmware image wr001_sample_firmware.bin lacks cryptographic signature headers or verification manifests.`
- **Threat Modeling & Attack Vector:** In a man-in-the-middle or physical attack scenario, an attacker can flash a modified firmware image containing persistent backdoors, rootkits, or malicious DNS redirectors because the bootloader and web flasher perform no cryptographic signature verification.
- **Security Impact:** Without cryptographic signatures, devices cannot verify the authenticity of firmware updates, leaving them susceptible to malicious firmware modification.
- **Recommended Mitigation:** Implement cryptographic signing (e.g. RSA-PSS or Ed25519) on all firmware upgrade packages and verify signatures before flashing.
- **Hardening Action Steps:**
  - 1. Implement cryptographic digital signature checking (e.g. Ed25519 / RSA-PSS) in the bootloader (U-Boot) and firmware upgrade CGI scripts.
  - 2. Reject any firmware package that fails signature validation prior to writing to flash memory.
  - 3. Embed the vendor public verification key in immutable bootloader memory.

### 13. [D1-F01] Telnet service exposed on local and upstream interfaces
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-319 (Cleartext Transmission) / CWE-259 (Hardcoded Password)
- **Category:** Network-Level Exposure / Insecure Defaults
- **Module:** Network Discovery
- **Threat Modeling & Attack Vector:** In a threat environment, an attacker connected to the Wi-Fi or upstream network can perform automated dictionary attacks (such as Mirai-style brute force) or sniff cleartext administrative commands and root credentials transmitted across the network.
- **Security Impact:** A local network attacker may reach the Telnet-like login service. If weak or hardcoded credentials exist, this may allow remote administrative or shell access.
- **Recommended Mitigation:** Disable Telnet by default and replace it with SSH only if remote administration is required.
- **Hardening Action Steps:**
  - 1. Remove the telnetd daemon from the device startup scripts (e.g. /etc/init.d/rcS).
  - 2. Block inbound TCP port 23 across all network interfaces using iptables firewall rules.
  - 3. Enforce cryptographic authentication (SSH) and disable default root accounts.

### 14. [D1-F_HTTP] Unencrypted HTTP management interface exposed
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-General Insecure Configuration
- **Category:** Network-Level Exposure / Insecure Defaults
- **Module:** Network Discovery
- **Security Impact:** Management traffic and credentials are transmitted in plaintext over the local wireless or wired network.
- **Recommended Mitigation:** Enforce HTTPS for all web management communications.

### 15. [D1-F_HTTP_ADMIN] Web management interface served over unencrypted HTTP
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-352 (Cross-Site Request Forgery)
- **Category:** Sensitive Data Exposure / Transport Security
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `Web interface responded on http://192.168.11.1/ without TLS encryption.`
- **Threat Modeling & Attack Vector:** An attacker on the same local Wi-Fi or upstream network can capture cleartext HTTP authentication traffic and session tokens via Wi-Fi sniffing or ARP spoofing. Without transport encryption or CSRF tokens, attackers can also forge router reconfiguration requests.
- **Security Impact:** All web interactions, login attempts, and configurations are sent in plaintext and vulnerable to local eavesdropping.
- **Recommended Mitigation:** Configure HTTPS encryption for the web management portal.
- **Hardening Action Steps:**
  - 1. Embed lightweight TLS support (e.g. mbedTLS / WolfSSL) into the embedded web server.
  - 2. Enable automatic redirection from HTTP port 80 to HTTPS port 443 with HSTS headers.
  - 3. Implement unique cryptographic certificates per device.

### 16. [D1-F03] Default admin credentials exposed in login page HTML
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-798 (Use of Hardcoded Credentials) / CWE-200 (Exposure of Sensitive Information)
- **Category:** Authentication Security / Insecure Defaults
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `Login page HTML contains hidden username or password values (e.g. 'admin').`
- **Threat Modeling & Attack Vector:** An attacker inspecting client-side HTML or automated crawlers can immediately harvest default administrative credentials without guessing or brute-forcing.
- **Security Impact:** The login page HTML reveals default credentials to anyone viewing the source code.
- **Recommended Mitigation:** Remove hardcoded credentials from client-side HTML.
- **Hardening Action Steps:**
  - 1. Remove all hardcoded default credentials from client-side HTML, JavaScript, and hidden form fields.
  - 2. Authenticate credentials strictly on the server side.
  - 3. Enforce a mandatory setup wizard requiring unique password configuration.

### 17. [D1-F04] Admin credentials stored in Base64 Authorization cookie
- **Severity:** High
- **Status:** Confirmed
- **Weakness Mapping:** CWE-312 (Cleartext Storage of Sensitive Information) / CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)
- **Category:** Session Management
- **Module:** Web Interface Checks
- **Observed Technical Evidence:** `Authorization cookie or script stores Base64 encoded credentials without HttpOnly/Secure flags.`
- **Threat Modeling & Attack Vector:** Because Base64 is trivially reversible and the cookie lacks HttpOnly/Secure flags, any client-side script (XSS) or local network eavesdropper can decode the plaintext admin credentials directly from the cookie header.
- **Security Impact:** The cookie can expose admin credentials because Base64 is reversible and the cookie lacks HttpOnly/Secure flags.
- **Recommended Mitigation:** Use secure server-side session tokens with HttpOnly, Secure and SameSite attributes.
- **Hardening Action Steps:**
  - 1. Implement cryptographically random session tokens (e.g. 128-bit tokens) stored in server memory.
  - 2. Set 'HttpOnly', 'Secure', and 'SameSite=Strict' flags on all session cookies.
  - 3. Never store credentials or reversible encodings in client cookies.

### 18. [D1-F_FW_UNAVAILABLE] Public firmware updates and vendor support unavailable
- **Severity:** Medium
- **Status:** Confirmed
- **Weakness Mapping:** CWE-1277 (Firmware Not Updateable) / CWE-1059 (Incomplete Documentation and Support)
- **Category:** Firmware Weaknesses / Lack of Vendor Transparency
- **Module:** Firmware Analysis
- **Observed Technical Evidence:** `Online discovery using queries: "https://192.168.11.1" firmware, "https://192.168.11.1" repeater update returned no official vendor firmware repositories or support portals.`
- **Threat Modeling & Attack Vector:** In a threat environment, when zero-day vulnerabilities or public CVEs (e.g. DNSpooq or Mirai exploits) affect embedded daemons, device owners cannot patch or update their repeaters, leaving them permanently vulnerable to automated botnets.
- **Security Impact:** The device manufacturer does not provide an official firmware update repository or public security patches, leaving known vulnerabilities unpatchable.
- **Recommended Mitigation:** Avoid using generic networking hardware that lacks transparent vendor support and ongoing security patch cycles.
- **Hardening Action Steps:**
  - 1. Establish a public, verifiable vendor security advisory portal.
  - 2. Provide cryptographically signed Over-the-Air (OTA) or manual firmware upgrade images.
  - 3. Publish transparent release notes and security vulnerability fixes.

## 4. Comprehensive Device Hardening & Defense Plan
1. Change default administrator passwords immediately upon deployment.
2. Disable unencrypted services such as Telnet and HTTP where possible.
3. Isolate repeater devices on a dedicated guest or test VLAN.
4. Verify firmware update availability from verified vendor sources.
