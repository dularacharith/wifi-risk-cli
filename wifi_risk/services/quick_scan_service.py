from datetime import datetime
from typing import Any, Callable, Optional

from wifi_risk.services.dns_service import auto_discover_setup_domain, query_dns_server
from wifi_risk.services.network_service import scan_ports_socket
from wifi_risk.services.web_service import analyze_html_content, fetch_web_page
from wifi_risk.utils.command_runner import is_tool_available, run_command_safe


def run_standalone_quick_scan(
    target_ip: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    """
    Perform a standalone, lightweight live vulnerability check on the target IP with real-time verbose progress reporting.
    Does not interact with the assessment database, PSR calculator or scoring engine.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if progress_callback:
        progress_callback(10, f"Initializing scan environment for target {target_ip}...")

    # 1. Port & Service Discovery
    open_ports = []
    scan_method = "socket"

    if is_tool_available("nmap"):
        from wifi_risk.services.network_service import run_nmap_scan

        if progress_callback:
            progress_callback(20, f"Running Nmap port & service probe on {target_ip}...")
        nmap_res = run_nmap_scan(target_ip)
        if nmap_res["success"]:
            open_ports = nmap_res["open_ports"]
            scan_method = "nmap"
        else:
            if progress_callback:
                progress_callback(25, f"Scanning TCP ports via Python sockets on {target_ip}...")
            open_ports = scan_ports_socket(target_ip)
    else:
        if progress_callback:
            progress_callback(25, f"Scanning TCP ports via Python sockets on {target_ip}...")
        open_ports = scan_ports_socket(target_ip)

    if progress_callback:
        progress_callback(50, f"Port discovery finished ({len(open_ports)} open ports discovered).")

    port_numbers = [p["port"] for p in open_ports]

    # 2. DNS Check (if port 53 is open)
    dns_status = "Closed / Inactive"
    dns_resolved_ips: list[str] = []
    if 53 in port_numbers:
        if progress_callback:
            progress_callback(60, f"Testing DNS query resolution and captive domain on {target_ip}:53...")
        dns_resolved_ips = query_dns_server("google.com", target_ip)
        discovered_domain, _ = auto_discover_setup_domain(target_ip, timeout=0.6)
        if discovered_domain:
            dns_status = f"Active & Captive ({discovered_domain})"
        elif dns_resolved_ips:
            dns_status = "Active & Resolving"
        else:
            dns_status = "Port Open (No DNS response)"
    else:
        if progress_callback:
            progress_callback(60, "DNS service port 53 is closed. Skipping DNS check.")

    # 3. Web Service Check (if port 80 or 8080 is open)
    web_status = "Closed / Inactive"
    web_details: dict[str, Any] = {}
    if 80 in port_numbers or 8080 in port_numbers:
        web_url = f"http://{target_ip}/"
        if progress_callback:
            progress_callback(75, f"Fetching and auditing web interface on {web_url}...")
        fetch_res = fetch_web_page(web_url, timeout=3.0)
        if not fetch_res["success"] and 8080 in port_numbers:
            web_url = f"http://{target_ip}:8080/"
            fetch_res = fetch_web_page(web_url, timeout=3.0)

        if fetch_res["success"]:
            web_status = f"Reachable on {web_url}"
            analysis = analyze_html_content(fetch_res["html"], base_url=web_url)
            web_details = {
                "url": web_url,
                "status_code": fetch_res["status_code"],
                "title": analysis.get("title", ""),
                "has_hidden_admin": analysis.get("has_hidden_admin", False),
                "has_basic_cookie_logic": analysis.get("has_basic_cookie_logic", False),
                "firmware_clue": analysis.get("firmware_clue", ""),
            }
        else:
            web_status = f"Port Open but no HTTP response on {web_url}"
    else:
        if progress_callback:
            progress_callback(75, "HTTP web ports 80/8080 are closed. Skipping web audit.")

    # 4. Compile Quick Security Observations & Detailed Alerts
    if progress_callback:
        progress_callback(90, "Evaluating vulnerability rules and compiling security alerts...")

    alerts: list[dict[str, str]] = []

    if 23 in port_numbers:
        alerts.append(
            {
                "level": "High",
                "severity": "High",
                "title": "Unencrypted Telnet Port Open (23/TCP)",
                "category": "Network Exposure / Insecure Defaults",
                "cwe": "CWE-319 (Cleartext Transmission) / CWE-259 (Hardcoded Credentials)",
                "description": "Telnet service allows plaintext command-line access and is vulnerable to network sniffing and brute force attacks.",
                "threat_scenario": "In a lab or local network attack scenario, an attacker connects to port 23 to perform automated dictionary attacks (such as Mirai-style brute force) or capture cleartext administrative commands and credentials.",
                "impact": "Unauthenticated or weak password access allows remote root shell access, enabling full device compromise and rogue firmware modifications.",
                "remediation": "Disable the Telnet service in the device management settings. If command-line administration is required, replace Telnet with SSH using key-based authentication.",
                "hardening_coverage": "1. Remove telnetd daemon from firmware startup scripts (/etc/init.d/rcS).\n2. Block inbound TCP port 23 on all interfaces via iptables.\n3. Enforce SSH with public-key cryptography.",
                "technical_details": f"TCP port 23 is actively listening on {target_ip}. Telnet protocol lacks cryptographic transport layer security.",
            }
        )

    if 21 in port_numbers:
        alerts.append(
            {
                "level": "Medium",
                "severity": "Medium",
                "title": "FTP Service Exposed (21/TCP)",
                "category": "Network Exposure / Plaintext Protocol",
                "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
                "threat_scenario": "An attacker on the same local network segment captures transmitted authentication credentials and files in transit using passive network sniffers (e.g. Wireshark/tcpdump).",
                "description": "FTP transmits credentials and file transfers in unencrypted plaintext.",
                "impact": "User credentials and transferred files can be captured by eavesdroppers on the local network segment using passive packet sniffers.",
                "remediation": "Disable the FTP server if not actively needed. Use SFTP (SSH File Transfer Protocol) or HTTPS for encrypted file management.",
                "hardening_coverage": "1. Disable the FTP daemon (e.g. vsftpd / bftpd) in device configuration.\n2. Restrict file management to authenticated HTTPS or SFTP.\n3. Block port 21 in firewall rules.",
                "technical_details": f"TCP port 21 is open on {target_ip}. The standard FTP protocol transmits all control and data streams without encryption.",
            }
        )

    if 80 in port_numbers and 443 not in port_numbers:
        alerts.append(
            {
                "level": "Medium",
                "severity": "Medium",
                "title": "Unencrypted HTTP Management Interface (80/TCP)",
                "category": "Transport Security / Sensitive Data Exposure",
                "cwe": "CWE-319 (Cleartext Transmission) / CWE-352 (Cross-Site Request Forgery)",
                "threat_scenario": "An attacker on the shared Wi-Fi network can intercept administrative sessions via ARP spoofing. Without CSRF protections on HTTP, an attacker can also trick a connected user into opening a web page that silently submits forged configuration commands (e.g. changing DNS or credentials) to the repeater.",
                "description": "Web management portal is served over plaintext HTTP without HTTPS encryption.",
                "impact": "Router configuration changes, administrator login sessions and Wi-Fi passphrase updates are transmitted in cleartext and exposed to local man-in-the-middle interception.",
                "remediation": "Enable and enforce HTTPS encryption for the web management portal with TLS certificates, and disable or redirect plaintext HTTP traffic.",
                "hardening_coverage": "1. Embed lightweight TLS (mbedTLS/WolfSSL) into the web server.\n2. Enforce automatic HTTP-to-HTTPS redirection with HSTS.\n3. Implement anti-CSRF tokens on all POST/GET configuration forms.\n4. Set secure cookie flags (HttpOnly, Secure, SameSite=Strict).",
                "technical_details": f"HTTP service responded on {web_details.get('url', f'http://{target_ip}/')}. No HTTPS (port 443) service was detected.",
            }
        )

    if web_details.get("has_hidden_admin"):
        alerts.append(
            {
                "level": "High",
                "severity": "High",
                "title": "Hardcoded Admin Credentials in Web HTML",
                "category": "Authentication Security / Insecure Defaults",
                "cwe": "CWE-798 (Use of Hardcoded Credentials)",
                "threat_scenario": "Any unauthenticated user or automated scanner on the network inspects the webpage HTML source code to extract the default username and password without needing to crack or brute-force anything.",
                "description": "The login page source code exposes default username and password values.",
                "impact": "Anyone viewing the webpage source code or client DOM tree can discover the default administrator credentials without performing any active exploitation.",
                "remediation": "Remove hardcoded credentials from client-side HTML templates. Implement secure server-side credential verification and mandate a unique password setup upon initial boot.",
                "hardening_coverage": "1. Remove default input value attributes (value='admin') from HTML templates.\n2. Enforce unique factory-generated passwords per unit on physical labels.\n3. Mandate password change during initial setup wizard.",
                "technical_details": "HTML inspection revealed hidden form fields containing hardcoded default credentials (e.g. 'admin').",
            }
        )

    if 53 in port_numbers:
        alerts.append(
            {
                "level": "Low",
                "severity": "Low",
                "title": "Local DNS Resolver Exposed (53/TCP)",
                "category": "Network Exposure / DNS Behavior",
                "cwe": "CWE-345 (Insufficient Verification) / CWE-400 (Amplification Abuse)",
                "threat_scenario": "In a lab attack scenario, an attacker targets the exposed DNS daemon (e.g. outdated dnsmasq) with forged response packets (DNS Cache Poisoning / DNSpooq) to trick the repeater into caching false IP addresses, redirecting all connected repeater clients to phishing portals.",
                "description": "Device runs an active DNS resolver responding to client lookup requests.",
                "impact": "If the DNS resolver accepts queries from untrusted interfaces or intercepts domain names, it can be abused for DNS spoofing or local cache poisoning.",
                "remediation": "Restrict DNS service listeners to authenticated client interfaces only and ensure DNS forwarding integrity is preserved.",
                "hardening_coverage": "1. Upgrade dnsmasq to version 2.83+ to patch DNSpooq vulnerabilities (CVE-2020-25681 - CVE-2020-25687).\n2. Bind DNS listener strictly to internal LAN interfaces.\n3. Enable source port randomization and DNSSEC validation.",
                "technical_details": f"TCP port 53 is open and responding on {target_ip} ({dns_status}).",
            }
        )

    # 5. Overall Status Tier
    has_high = any((a.get("severity") or a.get("level", "")).lower() in ["critical", "high"] for a in alerts)
    has_med = any("medium" in (a.get("severity") or a.get("level", "")).lower() for a in alerts)

    if has_high:
        overall_status = "High Vulnerability Exposure"
        status_color = "red"
    elif has_med:
        overall_status = "Medium Risk / Unencrypted Services"
        status_color = "yellow"
    elif len(open_ports) > 0:
        overall_status = "Low Risk / Standard Services Only"
        status_color = "green"
    else:
        overall_status = "Clean / No Common Management Ports Open"
        status_color = "green"

    if progress_callback:
        progress_callback(100, "Quick vulnerability check completed!")

    return {
        "target_ip": target_ip,
        "scan_time": scan_time,
        "scan_method": scan_method,
        "open_ports": open_ports,
        "dns_status": dns_status,
        "dns_resolved_ips": dns_resolved_ips,
        "web_status": web_status,
        "web_details": web_details,
        "alerts": alerts,
        "overall_status": overall_status,
        "status_color": status_color,
    }
