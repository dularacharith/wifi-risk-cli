import re
import socket
from datetime import datetime
from typing import Any, Callable, Optional

from wifi_risk.services.assessment_service import add_assessment_check
from wifi_risk.services.finding_service import import_findings
from wifi_risk.utils.command_runner import is_tool_available, run_command_safe
from wifi_risk.utils.file_loader import save_json

DEFAULT_PORTS = [21, 22, 23, 53, 80, 443, 554, 1900, 5000, 5555, 8080, 8443, 49152]

PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "domain (DNS)",
    80: "http",
    443: "https",
    554: "rtsp",
    1900: "ssdp",
    5000: "upnp",
    5555: "adb/debug",
    8080: "http-proxy",
    8443: "https-alt",
    49152: "upnp-alt",
}


def scan_ports_socket(
    target_ip: str,
    ports: list[int] | None = None,
    timeout: float = 0.8,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> list[dict[str, Any]]:
    """
    Perform a safe TCP port scan using Python sockets without external dependencies.
    """
    scan_ports = ports or DEFAULT_PORTS
    open_ports: list[dict[str, Any]] = []
    total_ports = len(scan_ports)

    for idx, port in enumerate(scan_ports, 1):
        service_name = PORT_SERVICE_MAP.get(port, "unknown")
        if progress_callback:
            percent = int((idx / total_ports) * 100)
            progress_callback(percent, f"Probing TCP port {port} ({service_name}) on {target_ip}...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                banner = ""
                try:
                    sock.settimeout(0.4)
                    banner_bytes = sock.recv(128)
                    banner = banner_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = ""

                open_ports.append(
                    {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_name,
                        "banner": banner,
                    }
                )
        except Exception:
            pass
        finally:
            sock.close()

    return open_ports


def parse_nmap_text(nmap_output: str) -> list[dict[str, Any]]:
    """
    Parse raw Nmap text output and extract open port details.
    """
    open_ports: list[dict[str, Any]] = []
    lines = nmap_output.splitlines()

    port_regex = re.compile(r"^(\d+)/([a-zA-Z]+)\s+([a-zA-Z|]+)\s+([^\s]+)(?:\s+(.*))?$")

    for line in lines:
        line_clean = line.strip()
        match = port_regex.match(line_clean)
        if match:
            port_num = int(match.group(1))
            protocol = match.group(2).lower()
            state = match.group(3).lower()
            service = match.group(4)
            version = match.group(5) or ""

            if "open" in state:
                open_ports.append(
                    {
                        "port": port_num,
                        "protocol": protocol,
                        "state": "open",
                        "service": service,
                        "banner": version.strip(),
                    }
                )

    return open_ports


def run_nmap_scan(target_ip: str, ports: list[int] | None = None) -> dict[str, Any]:
    """
    Execute an Nmap service scan if Nmap is installed on the host.
    """
    if not is_tool_available("nmap"):
        return {
            "success": False,
            "raw_output": "",
            "open_ports": [],
            "error": "Nmap is not installed or not in system PATH.",
        }

    scan_ports = ports or DEFAULT_PORTS
    ports_str = ",".join(str(p) for p in scan_ports)

    args = ["nmap", "-Pn", "-sV", "-p", ports_str, target_ip]
    res = run_command_safe(args, timeout=30)

    if not res["success"]:
        return {
            "success": False,
            "raw_output": res.get("stderr", ""),
            "open_ports": [],
            "error": res.get("stderr", "Nmap execution failed"),
        }

    raw_output = res.get("stdout", "")
    open_ports = parse_nmap_text(raw_output)

    return {
        "success": True,
        "raw_output": raw_output,
        "open_ports": open_ports,
        "error": None,
    }


def evaluate_network_rules(device_id: str, assessment_id: str, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Evaluate discovered open ports against security rules and return confirmed findings.
    """
    findings: list[dict[str, Any]] = []
    port_numbers = {p["port"] for p in open_ports}

    if 23 in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F01",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Telnet service exposed on local and upstream interfaces",
                "category": "Network-Level Exposure / Insecure Defaults",
                "severity": "High",
                "status": "Confirmed",
                "cwe": "CWE-319 (Cleartext Transmission) / CWE-259 (Hardcoded Password)",
                "threat_scenario": "In a lab or local threat environment, an attacker connected to the Wi-Fi or upstream network can perform automated dictionary attacks (such as Mirai-style brute force) or sniff cleartext administrative commands and root credentials transmitted across the network.",
                "impact": "Unauthenticated or weak password access allows remote root shell execution, enabling an attacker to compromise the repeater, modify routing tables, install persistent backdoors, or recruit the device into a botnet.",
                "recommendation": "Disable the Telnet daemon in firmware by default. Use SSH with key-based authentication if remote shell access is necessary.",
                "hardening_coverage": "1. Remove the telnetd daemon from the device startup scripts (e.g. /etc/init.d/rcS).\n2. Block inbound TCP port 23 across all network interfaces using iptables firewall rules.\n3. Enforce cryptographic authentication (SSH) and disable default root accounts.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if 21 in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F_FTP",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Cleartext FTP service exposed on local interface",
                "category": "Network-Level Exposure / Insecure Services",
                "severity": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-287 (Improper Authentication)",
                "threat_scenario": "In a threat environment, an attacker on the same local network segment can sniff cleartext FTP credentials or configuration files using passive network capture tools.",
                "impact": "Transmits administrative credentials and device backup archives in plaintext without encryption.",
                "recommendation": "Disable the unencrypted FTP daemon or migrate to secure SFTP/SCP for file transfers.",
                "hardening_coverage": "1. Remove legacy ftpd / vsftpd daemons from init scripts.\n2. Restrict file transfer operations to authenticated SSH/SFTP.\n3. Block port 21 on all external and guest interfaces.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if (80 in port_numbers or 8080 in port_numbers) and 443 not in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F_HTTP",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Unencrypted HTTP management interface exposed",
                "category": "Network-Level Exposure / Insecure Defaults",
                "severity": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-319 (Cleartext Transmission) / CWE-352 (Cross-Site Request Forgery)",
                "threat_scenario": "In a threat environment, an attacker on the same Wi-Fi network can intercept administrative sessions via ARP spoofing or Wi-Fi sniffing. Furthermore, without CSRF protections on unencrypted HTTP, an attacker can trick a logged-in user into visiting a malicious webpage that invisibly submits forged configuration requests (e.g. changing DNS servers or Wi-Fi keys) to the repeater.",
                "impact": "Cleartext transmission of Wi-Fi passphrases and admin credentials allows passive eavesdropping, session hijacking and unauthorized router reconfiguration via Cross-Site Request Forgery.",
                "recommendation": "Enforce HTTPS (TLS 1.2/1.3) encryption for all web management communications and implement anti-CSRF token verification.",
                "hardening_coverage": "1. Build and embed lightweight TLS support (e.g. mbedTLS / WolfSSL) into the embedded web server (e.g. uHTTPd / GoAhead / Boa).\n2. Enable automatic redirection from HTTP port 80 to HTTPS port 443 with HSTS headers.\n3. Generate a unique self-signed certificate upon first boot.\n4. Implement CSRF tokens for all state-changing administrative actions.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if 53 in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F05",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "DNS resolver exposed on management interface",
                "category": "Network-Level Exposure / DNS Behavior",
                "severity": "Low-Medium",
                "status": "Confirmed",
                "cwe": "CWE-345 (Insufficient Verification of Data Authenticity) / CWE-400 (Resource Amplification)",
                "threat_scenario": "In a threat environment, an outdated or misconfigured DNS daemon (such as legacy dnsmasq versions) can be targeted for DNS Cache Poisoning (DNSpooq series) or DNS Spoofing attacks. An attacker can forge DNS responses to poison the repeater's cache, redirecting all connected users from legitimate domains (such as banking or social media) to malicious phishing servers.",
                "impact": "Allows local man-in-the-middle traffic redirection, phishing interception, domain hijacking and potential upstream DNS leakage.",
                "recommendation": "Update the DNS resolver daemon to the latest patched version, enforce strict query filtering and validate DNS forwarding behavior.",
                "hardening_coverage": "1. Upgrade dnsmasq to version 2.83 or later to mitigate DNSpooq vulnerability advisories (CVE-2020-25681 through CVE-2020-25687).\n2. Configure the DNS server to listen exclusively on the internal LAN interface (bind-interfaces).\n3. Enable source port randomization and DNSSEC query verification in dnsmasq configuration.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if 554 in port_numbers or 8554 in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F_RTSP",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Exposed RTSP streaming daemon on device interface",
                "category": "Network-Level Exposure / Insecure Services",
                "severity": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-306 (Missing Authentication for Critical Function) / CWE-200 (Information Exposure)",
                "threat_scenario": "An attacker on the local network can connect to the exposed RTSP service port to stream multimedia feeds or probe for unauthenticated stream endpoints.",
                "impact": "Exposes unauthenticated multimedia streams and potential buffer overflow vulnerabilities in embedded media daemons.",
                "recommendation": "Disable RTSP service if unused or require strong RTSP authentication over TLS.",
                "hardening_coverage": "1. Disable embedded RTSP daemons on network repeaters.\n2. Enforce digest authentication for media streams.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if any(p in port_numbers for p in [1900, 5000, 49152]):
        findings.append(
            {
                "id": f"{device_id}-F_UPNP",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Exposed UPnP / SSDP service daemon",
                "category": "Network-Level Exposure / Insecure Protocols",
                "severity": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-287 (Improper Authentication) / CWE-306 (Missing Authentication for Critical Function)",
                "threat_scenario": "An attacker or infected host on the network can leverage unauthenticated UPnP IGD commands to open arbitrary port forwards (CallStranger/MiniUPnPd exploits).",
                "impact": "Allows malicious automatic WAN-to-LAN port mappings and network boundary bypass without administrative authorization.",
                "recommendation": "Disable UPnP by default on embedded repeaters and require administrative confirmation for port mappings.",
                "hardening_coverage": "1. Disable miniupnpd in firmware configuration.\n2. Block WAN and guest interface access to SSDP/UPnP ports.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    if 5555 in port_numbers or 9000 in port_numbers:
        findings.append(
            {
                "id": f"{device_id}-F_DEBUG",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Active debugging / test daemon exposed in production firmware",
                "category": "Insecure Defaults / Leftover Debug Code",
                "severity": "High",
                "status": "Confirmed",
                "cwe": "CWE-489 (Active Debug Code) / CWE-284 (Improper Access Control)",
                "threat_scenario": "An attacker can connect to the leftover diagnostic/ADB port to execute arbitrary system commands with root privileges.",
                "impact": "Unrestricted administrative execution and full device takeover via unauthenticated debug daemons.",
                "recommendation": "Remove all factory test and debugging daemons before final production firmware builds.",
                "hardening_coverage": "1. Strip engineering build flags (CONFIG_DEBUG) from production releases.\n2. Ensure no test daemons bind to TCP sockets in rcS.",
                "module": "Network Discovery",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    return findings


def perform_network_discovery(
    target_ip: str,
    device_id: str,
    assessment_id: str,
    raw_nmap_text: str | None = None,
    force_socket: bool = False,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    """
    Perform complete network discovery via Nmap or socket scan, generate findings and store evidence.
    """
    scan_method = "socket"
    open_ports: list[dict[str, Any]] = []
    raw_output = ""

    if raw_nmap_text:
        scan_method = "nmap_import"
        raw_output = raw_nmap_text
        open_ports = parse_nmap_text(raw_nmap_text)
    elif not force_socket and is_tool_available("nmap"):
        if progress_callback:
            progress_callback(10, f"Executing Nmap service banner scan on {target_ip}...")
        nmap_res = run_nmap_scan(target_ip)
        if nmap_res["success"]:
            scan_method = "nmap_live"
            raw_output = nmap_res["raw_output"]
            open_ports = nmap_res["open_ports"]
            if progress_callback:
                progress_callback(90, f"Nmap scan complete! Found {len(open_ports)} open port(s)...")
        else:
            scan_method = "socket_fallback"
            open_ports = scan_ports_socket(target_ip, progress_callback=progress_callback)
    else:
        scan_method = "socket"
        open_ports = scan_ports_socket(target_ip, progress_callback=progress_callback)

    findings = evaluate_network_rules(device_id, assessment_id, open_ports)

    evidence_data = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_ip": target_ip,
        "scan_method": scan_method,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": open_ports,
        "raw_output": raw_output,
        "findings": findings,
    }

    evidence_file = f"data/evidence/{assessment_id}_network.json"
    save_json(evidence_file, evidence_data)

    check_record = {
        "module": "Network Discovery",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "scan_method": scan_method,
        "open_ports_count": len(open_ports),
        "open_ports": [p["port"] for p in open_ports],
        "findings_count": len(findings),
        "evidence_file": evidence_file,
    }

    add_assessment_check(assessment_id, check_record)

    if findings:
        import_findings(findings)

    if progress_callback:
        progress_callback(100, "Network discovery completed!")

    return {
        "assessment_id": assessment_id,
        "target_ip": target_ip,
        "scan_method": scan_method,
        "open_ports": open_ports,
        "findings": findings,
        "evidence_file": evidence_file,
    }
