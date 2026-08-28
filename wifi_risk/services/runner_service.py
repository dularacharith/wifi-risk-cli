import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from wifi_risk.services.assessment_service import (
    create_assessment,
    get_assessment_by_id,
    update_assessment,
)
from wifi_risk.services.dns_service import perform_dns_checks
from wifi_risk.services.finding_service import (
    count_findings_by_severity,
    get_findings_by_assessment_id,
    import_findings,
)
from wifi_risk.services.firmware_service import (
    perform_firmware_static_analysis,
    perform_online_firmware_discovery,
)
from wifi_risk.services.network_service import perform_network_discovery
from wifi_risk.services.scoring_service import evaluate_device_security
from wifi_risk.services.web_service import perform_web_checks
from wifi_risk.utils.file_loader import save_json
from wifi_risk.utils.network_detector import get_auto_target_ip


def run_full_safe_assessment(
    target_ip: str = "auto",
    device_id: str = "Target-Device",
    price_lkr: int = 0,
    assessment_id: str | None = None,
    setup_domain: str = "",
    control_domain: str = "google.com",
    upstream_ip: str | None = None,
    raw_nmap_text: str | None = None,
    target_url: str | None = None,
    raw_html: str | None = None,
    observed_login_url: str | None = None,
    manual_web_observations: dict[str, Any] | None = None,
    brand: str = "",
    model: str = "",
    firmware_version: str = "",
    hardware_version: str = "",
    vendor_clue: str = "",
    firmware_file_path: str | None = None,
    notes: str = "Live security assessment execution",
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    """
    Execute safe assessment modules against available target services only with real-time verbose progress reporting.
    No mock data or assumed vulnerabilities are evaluated.
    """
    # 0. Resolve target IP if set to auto
    if progress_callback:
        progress_callback(5, "Resolving target IP address and routing interface...")

    if not target_ip or target_ip.lower() == "auto":
        target_ip = get_auto_target_ip(fallback="192.168.11.1")

    # 1. Assessment Initialization
    if progress_callback:
        progress_callback(10, f"Initializing assessment session for target {target_ip} ({device_id})...")

    if assessment_id:
        asm = get_assessment_by_id(assessment_id)
        if not asm:
            asm = create_assessment(
                device_id=device_id,
                target_ip=target_ip,
                price_lkr=price_lkr,
                notes=notes,
                metadata={"setup_domain": setup_domain},
            )
            assessment_id = asm["id"]
    else:
        asm = create_assessment(
            device_id=device_id,
            target_ip=target_ip,
            price_lkr=price_lkr,
            notes=notes,
            metadata={"setup_domain": setup_domain},
        )
        assessment_id = asm["id"]

    all_findings: list[dict[str, Any]] = []
    modules_run = []

    # 2. Network Discovery Module (Always runs to detect genuinely open ports)
    if progress_callback:
        progress_callback(20, f"Running Network Discovery (Scanning management ports on {target_ip})...")

    net_result = perform_network_discovery(
        target_ip=target_ip,
        device_id=device_id,
        assessment_id=assessment_id,
        raw_nmap_text=raw_nmap_text,
    )
    all_findings.extend(net_result.get("findings", []))
    modules_run.append("Network Discovery")

    open_ports = [p["port"] for p in net_result.get("open_ports", [])]
    is_http_open = (80 in open_ports) or (8080 in open_ports)
    is_dns_open = 53 in open_ports

    # 3. DNS Behavior Checks Module (Runs if DNS port is open or setup domain provided)
    dns_result: dict[str, Any] = {"setup_ips": [], "control_ips": [], "findings": []}
    if is_dns_open or setup_domain:
        if progress_callback:
            progress_callback(40, f"Executing DNS Behavior Checks on {target_ip} (Domain: '{setup_domain or 'General DNS'}')...")
        dns_result = perform_dns_checks(
            target_ip=target_ip,
            device_id=device_id,
            assessment_id=assessment_id,
            setup_domain=setup_domain,
            control_domain=control_domain,
            upstream_ip=upstream_ip,
        )
        all_findings.extend(dns_result.get("findings", []))
        modules_run.append("DNS Checks")
    else:
        if progress_callback:
            progress_callback(40, "DNS port is closed and no setup domain provided. Bypassing DNS checks.")

    # 4. Web Interface Checks Module (Runs if HTTP is open, or target_url/html provided)
    web_result: dict[str, Any] = {"findings": [], "is_reachable": False}
    web_url = target_url or f"http://{target_ip}/"
    if is_http_open or raw_html or manual_web_observations:
        if progress_callback:
            progress_callback(60, f"Running Web Interface & Authentication Checks on {web_url}...")
        web_result = perform_web_checks(
            target_ip=target_ip,
            device_id=device_id,
            assessment_id=assessment_id,
            target_url=web_url,
            raw_html=raw_html,
            observed_login_url=observed_login_url,
            manual_observations=manual_web_observations,
        )
        all_findings.extend(web_result.get("findings", []))
        modules_run.append("Web Interface Checks")
    else:
        if progress_callback:
            progress_callback(60, "Web management ports 80/8080 are closed. Bypassing web checks.")

    # 5. Firmware Analysis Module (Runs ONLY if user provided brand/model/version clues)
    has_fw_clues = bool(brand or model or firmware_version)
    fw_discovery_result: dict[str, Any] = {"discovery": {"found": False}, "findings": []}
    if has_fw_clues:
        if progress_callback:
            progress_callback(75, f"Performing Online Firmware Discovery for brand '{brand}' model '{model}'...")
        fw_discovery_result = perform_online_firmware_discovery(
            device_id=device_id,
            assessment_id=assessment_id,
            brand=brand,
            model=model,
            firmware_version=firmware_version,
            hardware_version=hardware_version,
            vendor_clue=vendor_clue,
            setup_domain=setup_domain,
        )
        all_findings.extend(fw_discovery_result.get("findings", []))
        modules_run.append("Firmware Discovery")
    else:
        if progress_callback:
            progress_callback(75, "No firmware clues provided. Skipping online firmware scraping.")

    # 6. Firmware Static Analysis (Runs ONLY if user explicitly supplied an existing firmware binary file)
    fw_static_result = None
    if firmware_file_path and Path(firmware_file_path).exists() and Path(firmware_file_path).is_file():
        if progress_callback:
            progress_callback(85, f"Running Static Binary Analysis on firmware image '{firmware_file_path}'...")
        fw_static_result = perform_firmware_static_analysis(
            file_path=firmware_file_path,
            device_id=device_id,
            assessment_id=assessment_id,
        )
        all_findings.extend(fw_static_result.get("findings", []))
        modules_run.append("Firmware Static Analysis")
    else:
        if progress_callback:
            progress_callback(85, "No local firmware binary specified. Skipping static binary analysis.")

    # 7. Central Findings Storage Import (Stores ONLY findings detected in this session)
    if progress_callback:
        progress_callback(90, f"Recording {len(all_findings)} discovered finding(s) to assessment session {assessment_id}...")
    if all_findings:
        import_findings(all_findings)

    # 8. Scoring and Recommendation Evaluation
    if progress_callback:
        progress_callback(95, "Evaluating 100-point security deduction scorecard and PSR metric...")
    evaluation = evaluate_device_security(
        device_id=device_id,
        assessment_id=assessment_id,
        custom_price=price_lkr,
    )

    # 9. Compile Unified Assessment Evidence
    summary_evidence = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_ip": target_ip,
        "price_lkr": price_lkr,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "modules_run": modules_run,
        "network_summary": {
            "open_ports": len(net_result.get("open_ports", [])),
            "findings_count": len(net_result.get("findings", [])),
            "evidence_file": net_result.get("evidence_file", ""),
        },
        "dns_summary": {
            "setup_domain_ips": dns_result.get("setup_ips", []),
            "control_domain_ips": dns_result.get("control_ips", []),
            "findings_count": len(dns_result.get("findings", [])),
            "evidence_file": dns_result.get("evidence_file", ""),
        },
        "web_summary": {
            "target_url": web_url,
            "findings_count": len(web_result.get("findings", [])),
            "evidence_file": web_result.get("evidence_file", ""),
        },
        "firmware_discovery_summary": {
            "performed": has_fw_clues,
            "found": fw_discovery_result.get("discovery", {}).get("found", False),
            "findings_count": len(fw_discovery_result.get("findings", [])),
            "evidence_file": fw_discovery_result.get("evidence_file", ""),
        },
        "firmware_static_summary": {
            "performed": fw_static_result is not None,
            "findings_count": len(fw_static_result.get("findings", [])) if fw_static_result else 0,
            "evidence_file": fw_static_result.get("evidence_file", "") if fw_static_result else "",
        },
        "evaluation": evaluation,
        "total_findings": len(all_findings),
    }

    full_evidence_file = f"data/evidence/{assessment_id}_full_assessment.json"
    save_json(full_evidence_file, summary_evidence)

    # 10. Update Assessment Record Status
    update_assessment(assessment_id, {"status": "Completed"})

    if progress_callback:
        progress_callback(100, "Full assessment completed successfully!")

    return {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_ip": target_ip,
        "price_lkr": price_lkr,
        "network_result": net_result,
        "dns_result": dns_result,
        "web_result": web_result,
        "firmware_discovery_result": fw_discovery_result,
        "firmware_static_result": fw_static_result,
        "all_findings": all_findings,
        "evaluation": evaluation,
        "full_evidence_file": full_evidence_file,
    }
