import re
import socket
from datetime import datetime
from typing import Any

from wifi_risk.services.assessment_service import add_assessment_check
from wifi_risk.services.finding_service import import_findings
from wifi_risk.utils.command_runner import is_tool_available, run_command_safe
from wifi_risk.utils.file_loader import save_json


def parse_nslookup_output(nslookup_text: str) -> list[str]:
    """
    Parse nslookup text output and extract resolved IP addresses.
    """
    ips: list[str] = []
    lines = nslookup_text.splitlines()

    after_first_address = False
    address_regex = re.compile(r"Address(?:es)?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    single_ip_regex = re.compile(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$")

    for line in lines:
        line_clean = line.strip()
        addr_match = address_regex.search(line_clean)
        if addr_match:
            ip = addr_match.group(1)
            if not after_first_address:
                after_first_address = True
            else:
                if ip not in ips:
                    ips.append(ip)
        elif after_first_address:
            single_match = single_ip_regex.match(line_clean)
            if single_match:
                ip = single_match.group(1)
                if ip not in ips:
                    ips.append(ip)

    if not ips:
        all_matches = address_regex.findall(nslookup_text)
        if len(all_matches) > 1:
            ips = list(set(all_matches[1:]))
        elif len(all_matches) == 1:
            ips = all_matches

    return ips


def query_dns_via_nslookup(domain: str, nameserver: str) -> list[str]:
    """
    Query DNS server using system nslookup utility.
    """
    if not is_tool_available("nslookup") or not domain:
        return []

    res = run_command_safe(["nslookup", domain, nameserver], timeout=5)
    if res["stdout"]:
        return parse_nslookup_output(res["stdout"])
    return []


def query_dns_via_dnspython(domain: str, nameserver: str, timeout: float = 2.5) -> list[str]:
    """
    Query DNS server using dnspython library if installed.
    """
    if not domain:
        return []
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.lifetime = timeout

        answers = resolver.resolve(domain, "A")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def query_dns_server(domain: str, nameserver: str, timeout: float = 2.5) -> list[str]:
    """
    Query a DNS server using dnspython with fallback to nslookup.
    """
    if not domain:
        return []
    ips = query_dns_via_dnspython(domain, nameserver, timeout=timeout)
    if not ips:
        ips = query_dns_via_nslookup(domain, nameserver)
    return ips


VENDOR_SETUP_DOMAINS = [
    "zrlogin.cn",         # Generic Chinese OEM (MT02, Pix-Link, LV-WR09)
    "wifi.repeater",      # Wavlink & Generic Realtek SOHO
    "myrepeater.net",     # Generic SOHO / Realtek
    "repeater.setup",     # Generic SOHO
    "ap.login",           # MediaTek / Realtek AP models
    "tplinkrepeater.net", # TP-Link
    "miwifi.com",         # Xiaomi Mi Wi-Fi
    "mywifiext.net",      # Netgear
    "re.tenda.cn",        # Tenda
]


def auto_discover_setup_domain(target_ip: str, timeout: float = 0.8) -> tuple[str, list[str]]:
    """
    Probe candidate vendor setup domains against the target resolver.
    Returns (domain, resolved_ips) for the first domain resolving to target_ip.
    """
    for candidate in VENDOR_SETUP_DOMAINS:
        ips = query_dns_server(candidate, target_ip, timeout=timeout)
        if target_ip in ips:
            return candidate, ips
    return "", []


def evaluate_dns_behavior(
    device_id: str,
    assessment_id: str,
    target_ip: str,
    setup_domain: str,
    control_domain: str,
    setup_resolved_ips: list[str],
    control_resolved_ips: list[str],
    upstream_ip: str | None = None,
    upstream_setup_ips: list[str] | None = None,
    upstream_control_ips: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate DNS resolution behavior against security rules and return confirmed findings.
    """
    findings: list[dict[str, Any]] = []

    # Rule 1: Upstream exposed DNS resolver redirecting setup domain
    if upstream_ip and upstream_setup_ips and setup_domain:
        if target_ip in upstream_setup_ips:
            findings.append(
                {
                    "id": f"{device_id}-F05",
                    "device_id": device_id,
                    "assessment_id": assessment_id,
                    "title": "DNS resolver exposed upstream with setup-domain redirection",
                    "category": "Network-Level Exposure / DNS Behavior",
                    "severity": "Low-Medium",
                    "status": "Confirmed",
                    "cwe": "CWE-345 (Insufficient Verification of Data Authenticity) / CWE-400 (Resource Amplification)",
                    "threat_scenario": "In a threat environment, an upstream attacker can send spoofed DNS responses or leverage the exposed DNS resolver for recursive query amplification and DNS cache poisoning (DNSpooq series CVE-2020-25681 through CVE-2020-25687).",
                    "evidence": f"The repeater exposes DNS resolver on upstream interface ({upstream_ip}) and resolves '{setup_domain}' to its internal IP ({target_ip}).",
                    "impact": f"The repeater exposes DNS resolver behavior on upstream interface ({upstream_ip}) and resolves setup domain '{setup_domain}' to its internal management IP ({target_ip}).",
                    "recommendation": "Restrict DNS service exposure to required local interfaces only.",
                    "hardening_coverage": "1. Configure the DNS daemon (dnsmasq) with 'bind-interfaces' and 'listen-address' pointing strictly to local LAN.\n2. Drop all inbound UDP/TCP port 53 traffic on the upstream WAN interface via iptables firewall rules.\n3. Enable DNSSEC query verification in resolver configuration.",
                    "module": "DNS Checks",
                    "date_observed": datetime.now().isoformat(timespec="seconds"),
                }
            )

    # Rule 2: Local DNS redirection of setup domain to management IP
    if setup_domain and target_ip in setup_resolved_ips:
        findings.append(
            {
                "id": f"{device_id}-F_DNS_REDIR",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": f"Setup domain '{setup_domain}' resolved to management IP ({target_ip})",
                "category": "Network-Level Exposure / DNS Behavior",
                "severity": "Low",
                "status": "Confirmed",
                "cwe": "CWE-345 (Insufficient Verification of Data Authenticity) / CWE-601 (URL Redirection to Untrusted Site)",
                "threat_scenario": "When a repeater redirects setup domains to its local IP, any unauthenticated browser session or background client application navigating to the domain is redirected into the repeater's web management portal.",
                "evidence": f"DNS query for '{setup_domain}' on {target_ip} resolved to {target_ip}.",
                "impact": f"The device built-in DNS server intercepts queries for '{setup_domain}' and directs users to the router admin portal.",
                "recommendation": "Ensure setup-domain resolution is isolated and cannot be abused for unexpected domain hijacking.",
                "hardening_coverage": "1. Restrict setup-domain local DNS override strictly to the initial unconfigured state.\n2. Ensure setup-domain redirection is terminated once configuration is completed.\n3. Validate internal query sources before applying DNS hijacking rules.",
                "module": "DNS Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    return findings


def perform_dns_checks(
    target_ip: str,
    device_id: str,
    assessment_id: str,
    setup_domain: str = "",
    control_domain: str = "google.com",
    upstream_ip: str | None = None,
    manual_setup_ips: list[str] | None = None,
    manual_control_ips: list[str] | None = None,
    manual_upstream_setup_ips: list[str] | None = None,
    manual_upstream_control_ips: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run or import DNS checks, analyze resolution differences, generate findings and record evidence.
    """
    if manual_setup_ips is not None:
        setup_ips = manual_setup_ips
        control_ips = manual_control_ips or []
        check_method = "manual_import"
    else:
        check_method = "live_query"
        if setup_domain:
            setup_ips = query_dns_server(setup_domain, target_ip)
        else:
            # Auto-probe known vendor setup domains against local resolver
            discovered_domain, discovered_ips = auto_discover_setup_domain(target_ip)
            if discovered_domain:
                setup_domain = discovered_domain
                setup_ips = discovered_ips
            else:
                setup_ips = []
        control_ips = query_dns_server(control_domain, target_ip) if control_domain else []

    up_setup_ips: list[str] = []
    up_control_ips: list[str] = []

    if upstream_ip:
        if manual_upstream_setup_ips is not None:
            up_setup_ips = manual_upstream_setup_ips
            up_control_ips = manual_upstream_control_ips or []
        else:
            up_setup_ips = query_dns_server(setup_domain, upstream_ip) if setup_domain else []
            up_control_ips = query_dns_server(control_domain, upstream_ip) if control_domain else []

    findings = evaluate_dns_behavior(
        device_id=device_id,
        assessment_id=assessment_id,
        target_ip=target_ip,
        setup_domain=setup_domain,
        control_domain=control_domain,
        setup_resolved_ips=setup_ips,
        control_resolved_ips=control_ips,
        upstream_ip=upstream_ip,
        upstream_setup_ips=up_setup_ips if upstream_ip else None,
        upstream_control_ips=up_control_ips if upstream_ip else None,
    )

    evidence_data = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_ip": target_ip,
        "upstream_ip": upstream_ip,
        "setup_domain": setup_domain,
        "control_domain": control_domain,
        "check_method": check_method,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target_dns_results": {
            "setup_domain_ips": setup_ips,
            "control_domain_ips": control_ips,
        },
        "upstream_dns_results": {
            "setup_domain_ips": up_setup_ips,
            "control_domain_ips": up_control_ips,
        } if upstream_ip else {},
        "findings": findings,
    }

    evidence_file = f"data/evidence/{assessment_id}_dns.json"
    save_json(evidence_file, evidence_data)

    check_record = {
        "module": "DNS Checks",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "check_method": check_method,
        "setup_domain": setup_domain,
        "setup_ips": setup_ips,
        "control_ips": control_ips,
        "upstream_ip": upstream_ip,
        "upstream_setup_ips": up_setup_ips,
        "findings_count": len(findings),
        "evidence_file": evidence_file,
    }

    add_assessment_check(assessment_id, check_record)

    if findings:
        import_findings(findings)

    return {
        "assessment_id": assessment_id,
        "target_ip": target_ip,
        "setup_domain": setup_domain,
        "setup_ips": setup_ips,
        "control_ips": control_ips,
        "upstream_ip": upstream_ip,
        "upstream_setup_ips": up_setup_ips,
        "findings": findings,
        "evidence_file": evidence_file,
    }
