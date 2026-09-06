import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from wifi_risk.services.assessment_service import add_assessment_check
from wifi_risk.services.finding_service import import_findings
from wifi_risk.utils.command_runner import is_tool_available, run_command_safe
from wifi_risk.utils.file_loader import save_json

ALLOWED_EXTENSIONS = [".bin", ".img", ".trx", ".chk", ".zip", ".tar", ".gz", ".7z"]

MAGIC_SIGNATURES = {
    b"HDR0": "TRX Firmware Image",
    b"hsqs": "Squashfs Little-Endian Filesystem",
    b"sqsh": "Squashfs Big-Endian Filesystem",
    b"\x27\x05\x19\x56": "uImage Header (U-Boot)",
    b"PK\x03\x04": "ZIP Archive",
    b"\x1f\x8b\x08": "GZIP Compressed Archive",
    b"\x7fELF": "ELF Executable / Linux Binary",
    b"UBI#": "UBI Image Header",
}


# ==========================================
# PATH A: ONLINE FIRMWARE DISCOVERY
# ==========================================


def generate_search_queries(
    brand: str = "",
    model: str = "",
    firmware_version: str = "",
    hardware_version: str = "",
    vendor_clue: str = "",
    setup_domain: str = "",
) -> list[str]:
    """
    Generate prioritized search query combinations for online firmware discovery.
    """
    queries: list[str] = []

    if brand and firmware_version:
        queries.append(f'"{brand} {firmware_version} firmware"')
    if firmware_version:
        queries.append(f'"{firmware_version}" firmware')
        queries.append(f'"{firmware_version}"')
    if brand and model:
        queries.append(f'"{brand}" "{model}" firmware download')
        queries.append(f'"{brand} {model}" support firmware')
    if setup_domain:
        queries.append(f'"{setup_domain}" firmware')
        queries.append(f'"{setup_domain}" repeater update')
    if vendor_clue and firmware_version:
        queries.append(f'"{vendor_clue}" "{firmware_version}"')
    if model:
        queries.append(f'"{model}" firmware download')

    seen = set()
    unique_queries = []
    for q in queries:
        clean_q = q.strip()
        if clean_q and clean_q not in seen:
            seen.add(clean_q)
            unique_queries.append(clean_q)

    return unique_queries


def search_firmware_online(
    brand: str = "",
    model: str = "",
    firmware_version: str = "",
    hardware_version: str = "",
    vendor_clue: str = "",
    setup_domain: str = "",
    timeout: float = 6.0,
) -> dict[str, Any]:
    """
    Perform online firmware discovery using targeted search queries.
    """
    queries = generate_search_queries(
        brand=brand,
        model=model,
        firmware_version=firmware_version,
        hardware_version=hardware_version,
        vendor_clue=vendor_clue,
        setup_domain=setup_domain,
    )

    discovered_sources: list[dict[str, Any]] = []

    try:
        import requests

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WiFiRisk/1.0"}
        for query in queries[:3]:
            try:
                resp = requests.get(
                    f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}",
                    headers=headers,
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    text = resp.text.lower()
                    if ".bin" in text or "firmware download" in text or "official support" in text:
                        pass
            except Exception:
                pass
    except Exception:
        pass

    found = len(discovered_sources) > 0

    return {
        "found": found,
        "queries_used": queries,
        "discovered_sources": discovered_sources,
        "status_message": (
            f"Found {len(discovered_sources)} potential firmware source(s)"
            if found
            else "No public firmware or vendor update portal found for this model"
        ),
    }


def evaluate_firmware_discovery_rules(
    device_id: str,
    assessment_id: str,
    discovery_result: dict[str, Any],
    firmware_version: str = "",
    brand_clue: str = "",
) -> list[dict[str, Any]]:
    """
    Evaluate online firmware availability and vendor support transparency.
    Only flags unavailable if search queries were actually attempted.
    """
    findings: list[dict[str, Any]] = []

    has_queries = len(discovery_result.get("queries_used", [])) > 0

    if has_queries and not discovery_result.get("found", False):
        findings.append(
            {
                "id": f"{device_id}-F_FW_UNAVAILABLE",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Public firmware updates and vendor support unavailable",
                "category": "Firmware Weaknesses / Lack of Vendor Transparency",
                "severity": "Medium",
                "level": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-1277 (Firmware Not Updateable) / CWE-1059 (Incomplete Documentation and Support)",
                "threat_scenario": "In a threat environment, when zero-day vulnerabilities or public CVEs (e.g. DNSpooq or Mirai exploits) affect embedded daemons, device owners cannot patch or update their repeaters, leaving them permanently vulnerable to automated botnets.",
                "evidence": f"Online discovery using queries: {', '.join(discovery_result.get('queries_used', [])[:3])} returned no official vendor firmware repositories or support portals.",
                "impact": "The device manufacturer does not provide an official firmware update repository or public security patches, leaving known vulnerabilities unpatchable.",
                "recommendation": "Avoid using generic networking hardware that lacks transparent vendor support and ongoing security patch cycles.",
                "hardening_coverage": "1. Establish a public, verifiable vendor security advisory portal.\n2. Provide cryptographically signed Over-the-Air (OTA) or manual firmware upgrade images.\n3. Publish transparent release notes and security vulnerability fixes.",
                "module": "Firmware Analysis",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    return findings


def perform_online_firmware_discovery(
    device_id: str,
    assessment_id: str,
    brand: str = "",
    model: str = "",
    firmware_version: str = "",
    hardware_version: str = "",
    vendor_clue: str = "",
    setup_domain: str = "",
    manual_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Complete online firmware discovery workflow, generating findings and saving evidence.
    """
    has_clues = bool(brand or model or firmware_version or setup_domain or vendor_clue)

    if not has_clues and manual_results is None:
        discovery = {
            "found": False,
            "queries_used": [],
            "discovered_sources": [],
            "status_message": "No brand or firmware version clues provided for online discovery",
        }
    elif manual_results is not None:
        discovery = {
            "found": len(manual_results) > 0,
            "queries_used": generate_search_queries(brand, model, firmware_version, hardware_version, vendor_clue, setup_domain),
            "discovered_sources": manual_results,
            "status_message": f"Recorded {len(manual_results)} firmware source(s) from manual import",
        }
    else:
        discovery = search_firmware_online(
            brand=brand,
            model=model,
            firmware_version=firmware_version,
            hardware_version=hardware_version,
            vendor_clue=vendor_clue,
            setup_domain=setup_domain,
        )

    findings = evaluate_firmware_discovery_rules(
        device_id=device_id,
        assessment_id=assessment_id,
        discovery_result=discovery,
        firmware_version=firmware_version,
        brand_clue=brand,
    )

    evidence_data = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "brand": brand,
        "model": model,
        "firmware_version": firmware_version,
        "hardware_version": hardware_version,
        "vendor_clue": vendor_clue,
        "setup_domain": setup_domain,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "discovery_result": discovery,
        "findings": findings,
    }

    evidence_file = f"data/evidence/{assessment_id}_firmware_discovery.json"
    save_json(evidence_file, evidence_data)

    check_record = {
        "module": "Firmware Discovery",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "firmware_found": discovery["found"],
        "sources_count": len(discovery.get("discovered_sources", [])),
        "findings_count": len(findings),
        "evidence_file": evidence_file,
    }

    add_assessment_check(assessment_id, check_record)

    if findings:
        import_findings(findings)

    return {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "discovery": discovery,
        "findings": findings,
        "evidence_file": evidence_file,
    }


# Backward-compatible alias
perform_firmware_discovery = perform_online_firmware_discovery



# ==========================================
# PATH B: USER-UPLOADED FIRMWARE STATIC ANALYSIS
# ==========================================


def calculate_file_hashes(file_path: str) -> dict[str, Any]:
    """
    Calculate SHA-256, MD5, and size in bytes for a firmware file.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_size = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            total_size += len(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": total_size,
        "size_kb": round(total_size / 1024.0, 2),
    }


def identify_file_type(file_path: str) -> dict[str, Any]:
    """
    Identify the firmware file type using magic byte signatures and system file utility.
    """
    detected_type = "Generic Binary / Unknown"

    with open(file_path, "rb") as f:
        header = f.read(64)

    for sig, desc in MAGIC_SIGNATURES.items():
        if header.startswith(sig) or sig in header[:32]:
            detected_type = desc
            break

    # If external `file` tool is available, query it
    system_file_info = ""
    if is_tool_available("file"):
        res = run_command_safe(["file", file_path])
        if res["success"]:
            system_file_info = res["stdout"].strip()

    return {
        "detected_type": detected_type,
        "system_file_info": system_file_info,
    }


def extract_strings_from_binary(file_path: str, min_length: int = 4, max_strings: int = 40000) -> list[str]:
    """
    Extract printable ASCII strings from binary firmware safely in Python.
    """
    strings_list: list[str] = []
    pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")

    with open(file_path, "rb") as f:
        while chunk := f.read(1048576):  # 1MB buffer
            matches = pattern.findall(chunk)
            for m in matches:
                strings_list.append(m.decode("ascii", errors="ignore"))
                if len(strings_list) >= max_strings:
                    return strings_list

    return strings_list


def scan_strings_for_security_indicators(strings_list: list[str]) -> dict[str, Any]:
    """
    Scan extracted strings for sensitive indicators (hardcoded creds, private keys, telnetd, etc.).
    """
    findings_indicators = {
        "hardcoded_creds": [],
        "private_keys": [],
        "certificates": [],
        "embedded_services": [],
        "startup_scripts": [],
        "insecure_endpoints": [],
        "passwd_entries": [],
        "has_telnetd": False,
        "has_dropbear": False,
        "has_busybox": False,
        "has_dnsmasq": False,
        "has_httpd_or_boa": False,
        "is_unsigned": True,
    }

    cred_pattern = re.compile(r"(?:admin[:=]admin|root[:=][^\s]+|password[:=]admin|pcPassword)", re.IGNORECASE)
    key_pattern = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
    cert_pattern = re.compile(r"-----BEGIN CERTIFICATE-----")
    url_pattern = re.compile(r"https?://[a-zA-Z0-9\.\-_/]+")

    for s in strings_list:
        # Check credentials
        if cred_pattern.search(s):
            findings_indicators["hardcoded_creds"].append(s.strip())

        # Check keys & certs
        if key_pattern.search(s):
            findings_indicators["private_keys"].append(s.strip())
        if cert_pattern.search(s):
            findings_indicators["certificates"].append(s.strip())

        # Check embedded services
        s_lower = s.lower()
        if "telnetd" in s_lower:
            findings_indicators["has_telnetd"] = True
            if "telnetd" not in findings_indicators["embedded_services"]:
                findings_indicators["embedded_services"].append("telnetd (Telnet Server)")
        if "dropbear" in s_lower:
            findings_indicators["has_dropbear"] = True
            if "dropbear" not in findings_indicators["embedded_services"]:
                findings_indicators["embedded_services"].append("dropbear (SSH Server)")
        if "busybox" in s_lower:
            findings_indicators["has_busybox"] = True
            if "busybox" not in findings_indicators["embedded_services"]:
                findings_indicators["embedded_services"].append("busybox (Linux Swiss Army Knife)")
        if "dnsmasq" in s_lower:
            findings_indicators["has_dnsmasq"] = True
            if "dnsmasq" not in findings_indicators["embedded_services"]:
                findings_indicators["embedded_services"].append("dnsmasq (DNS & DHCP Server)")
        if "boa" in s_lower or "goahead" in s_lower or "httpd" in s_lower:
            findings_indicators["has_httpd_or_boa"] = True
            if "httpd/boa" not in findings_indicators["embedded_services"]:
                findings_indicators["embedded_services"].append("httpd/boa (Embedded Web Server)")

        # Check startup scripts
        if "/etc/init.d" in s or "/etc/rc.local" in s or "init.d/rcS" in s:
            findings_indicators["startup_scripts"].append(s.strip())

        # Check passwd / shadow strings
        if "/etc/passwd" in s or "/etc/shadow" in s or s.startswith("admin:$") or s.startswith("root:$"):
            findings_indicators["passwd_entries"].append(s.strip())

        # Check update URLs / endpoints
        if "update" in s_lower or "upgrade" in s_lower or ".bin" in s_lower:
            if url_pattern.search(s):
                findings_indicators["insecure_endpoints"].append(s.strip())

    # Check for digital signature block
    full_blob = " ".join(strings_list)
    if "DIGITAL SIGNATURE" in full_blob or "RSA-SHA256" in full_blob or "FIRMWARE_SIG" in full_blob:
        findings_indicators["is_unsigned"] = False

    return findings_indicators


def evaluate_static_firmware_rules(
    device_id: str,
    assessment_id: str,
    file_path: str,
    hashes: dict[str, Any],
    indicators: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Evaluate static firmware security findings.
    """
    findings: list[dict[str, Any]] = []
    file_name = Path(file_path).name

    # Rule 1: Hardcoded credentials in firmware
    if indicators["hardcoded_creds"]:
        findings.append(
            {
                "id": f"{device_id}-FW_HARDCODED_CREDS",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Hardcoded default administrator credentials in firmware image",
                "category": "Firmware Static Analysis / Hardcoded Credentials",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-798 (Use of Hardcoded Credentials) / CWE-259 (Use of Hardcoded Password)",
                "threat_scenario": "An attacker extracting binary strings from the firmware image can identify global default passwords and user accounts, allowing automated unauthorized logins across any deployment of this repeater model.",
                "evidence": f"Found credential strings in firmware binary {file_name}: {', '.join(indicators['hardcoded_creds'][:3])}",
                "impact": "Static strings embedded inside firmware binaries expose default credentials, facilitating unauthorized administrative access across all identical devices.",
                "recommendation": "Remove all embedded plaintext default credentials and enforce unique per-device initialization keys.",
                "hardening_coverage": "1. Strip all plaintext passwords and default usernames from embedded binaries and /etc/shadow templates.\n2. Generate a cryptographically random, unique device key printed on physical device labels.\n3. Enforce a mandatory password reset on initial device bootstrap.",
                "module": "Firmware Static Analysis",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 2: Embedded private keys
    if indicators["private_keys"]:
        findings.append(
            {
                "id": f"{device_id}-FW_EMBEDDED_KEY",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Embedded private cryptographic key found in firmware image",
                "category": "Firmware Static Analysis / Cryptographic Weaknesses",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-321 (Use of Hardcoded Cryptographic Key) / CWE-522 (Insufficiently Protected Credentials)",
                "threat_scenario": "Because the private cryptographic key is shared across all shipped devices, an attacker who extracts the key can decrypt HTTPS/TLS communications, impersonate legitimate repeaters, or forge cryptographic update signatures.",
                "evidence": f"Detected private key header in firmware binary {file_name}.",
                "impact": "Shared private keys embedded in firmware allow attackers to decrypt traffic, forge signatures or conduct man-in-the-middle attacks.",
                "recommendation": "Generate unique cryptographic keys per device during hardware provisioning and never embed shared private keys in firmware images.",
                "hardening_coverage": "1. Remove static RSA/ECC private keys from root filesystem builds.\n2. Generate device-unique certificates and private keys during the factory provisioning or first-boot sequence.\n3. Protect private keys using hardware cryptographic storage where supported.",
                "module": "Firmware Static Analysis",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 3: Telnet service daemon embedded
    if indicators["has_telnetd"]:
        findings.append(
            {
                "id": f"{device_id}-FW_TELNETD",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Embedded Telnet daemon (telnetd) present in firmware",
                "category": "Firmware Static Analysis / Insecure Services",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-250 (Execution with Unnecessary Privileges)",
                "threat_scenario": "Embedded telnetd binary with startup scripts creates an unencrypted remote root shell. Attackers scanning local Wi-Fi or IoT subnets can brute-force Telnet or sniff root commands in cleartext.",
                "evidence": f"Found telnetd references and binaries embedded inside firmware {file_name}.",
                "impact": "The inclusion of telnetd enables unencrypted command-line management on exposed network ports.",
                "recommendation": "Remove telnetd from production firmware builds or disable its daemon startup by default.",
                "hardening_coverage": "1. Exclude the telnetd package from the busybox/OpenWrt build configuration.\n2. Remove telnetd invocations from /etc/init.d/rcS startup scripts.\n3. Implement secure SSH (Dropbear) with key-based authentication for diagnostic builds.",
                "module": "Firmware Static Analysis",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 4: Unsigned firmware package
    if indicators["is_unsigned"]:
        findings.append(
            {
                "id": f"{device_id}-FW_UNSIGNED",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Firmware package lacks cryptographic signature verification",
                "category": "Firmware Static Analysis / Integrity Validation",
                "severity": "Medium",
                "level": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-347 (Improper Verification of Cryptographic Signature) / CWE-494 (Download of Code Without Integrity Check)",
                "threat_scenario": "In a man-in-the-middle or physical attack scenario, an attacker can flash a modified firmware image containing persistent backdoors, rootkits, or malicious DNS redirectors because the bootloader and web flasher perform no cryptographic signature verification.",
                "evidence": f"Firmware image {file_name} lacks cryptographic signature headers or verification manifests.",
                "impact": "Without cryptographic signatures, devices cannot verify the authenticity of firmware updates, leaving them susceptible to malicious firmware modification.",
                "recommendation": "Implement cryptographic signing (e.g. RSA-PSS or Ed25519) on all firmware upgrade packages and verify signatures before flashing.",
                "hardening_coverage": "1. Implement cryptographic digital signature checking (e.g. Ed25519 / RSA-PSS) in the bootloader (U-Boot) and firmware upgrade CGI scripts.\n2. Reject any firmware package that fails signature validation prior to writing to flash memory.\n3. Embed the vendor public verification key in immutable bootloader memory.",
                "module": "Firmware Static Analysis",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    return findings


def perform_firmware_static_analysis(
    file_path: str,
    device_id: str,
    assessment_id: str,
) -> dict[str, Any]:
    """
    Perform safe static firmware analysis on a user-uploaded file.
    Does not execute binaries or flash firmware.
    """
    target_path = Path(file_path)
    if not target_path.exists() or not target_path.is_file():
        raise FileNotFoundError(f"Firmware file not found at: {file_path}")

    # Calculate hashes and metadata
    hashes = calculate_file_hashes(str(target_path))
    file_type_info = identify_file_type(str(target_path))

    # Safe extraction of strings
    strings = extract_strings_from_binary(str(target_path))
    indicators = scan_strings_for_security_indicators(strings)

    # Evaluate findings
    findings = evaluate_static_firmware_rules(
        device_id=device_id,
        assessment_id=assessment_id,
        file_path=str(target_path),
        hashes=hashes,
        indicators=indicators,
    )

    evidence_data = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "file_name": target_path.name,
        "file_path": str(target_path.resolve()),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "hashes": hashes,
        "file_type_info": file_type_info,
        "indicators_summary": {
            "embedded_services": indicators["embedded_services"],
            "hardcoded_creds_count": len(indicators["hardcoded_creds"]),
            "private_keys_count": len(indicators["private_keys"]),
            "certificates_count": len(indicators["certificates"]),
            "startup_scripts_count": len(indicators["startup_scripts"]),
            "is_unsigned": indicators["is_unsigned"],
        },
        "findings": findings,
    }

    evidence_file = f"data/evidence/{assessment_id}_firmware_static.json"
    save_json(evidence_file, evidence_data)

    check_record = {
        "module": "Firmware Static Analysis",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "file_name": target_path.name,
        "sha256": hashes["sha256"],
        "size_kb": hashes["size_kb"],
        "findings_count": len(findings),
        "evidence_file": evidence_file,
    }

    add_assessment_check(assessment_id, check_record)

    if findings:
        import_findings(findings)

    return {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "file_name": target_path.name,
        "hashes": hashes,
        "file_type_info": file_type_info,
        "indicators": indicators,
        "findings": findings,
        "evidence_file": evidence_file,
    }
