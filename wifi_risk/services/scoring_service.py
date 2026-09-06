from typing import Any

from wifi_risk.services.assessment_service import get_assessment_by_id
from wifi_risk.services.device_service import get_device_by_id
from wifi_risk.services.finding_service import (
    count_findings_by_severity,
    get_findings_by_assessment_id,
    get_findings_by_device_id,
)

BASE_SCORE = 100
BASELINE_PREMIUM_PRICE = 15000

SEVERITY_DEDUCTIONS = {
    "High": 12,
    "Medium": 8,
    "Low-Medium": 5,
    "Low": 3,
    "Informational": 1,
}


def calculate_security_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calculate the security score by deducting points from 100 based on finding severities.
    """
    score = BASE_SCORE
    deductions_detail: list[dict[str, Any]] = []

    for f in findings:
        sev = f.get("severity") or f.get("level") or "Informational"
        # Match standard or normalized severity key
        deduction = SEVERITY_DEDUCTIONS.get(sev)
        if deduction is None:
            sev_norm = sev.strip().lower()
            if sev_norm in ["critical", "high"]:
                deduction = SEVERITY_DEDUCTIONS["High"]
            elif "low-medium" in sev_norm:
                deduction = SEVERITY_DEDUCTIONS["Low-Medium"]
            elif "medium" in sev_norm:
                deduction = SEVERITY_DEDUCTIONS["Medium"]
            elif "low" in sev_norm:
                deduction = SEVERITY_DEDUCTIONS["Low"]
            else:
                deduction = SEVERITY_DEDUCTIONS.get("Informational", 1)

        score -= deduction
        deductions_detail.append(
            {
                "finding_id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": sev,
                "deduction": deduction,
            }
        )

    # Bound score between 0 and 100
    final_score = max(0, min(100, score))
    total_deductions = BASE_SCORE - final_score

    return {
        "base_score": BASE_SCORE,
        "final_score": final_score,
        "total_deductions": total_deductions,
        "deductions_detail": deductions_detail,
    }


def determine_risk_level(security_score: int) -> str:
    """
    Determine risk tier from security score.
    80 to 100: Low
    60 to 79: Medium
    40 to 59: High
    0 to 39: Critical
    """
    if security_score >= 80:
        return "Low"
    if security_score >= 60:
        return "Medium"
    if security_score >= 40:
        return "High"
    return "Critical"


def calculate_psr(
    security_score: int,
    price_lkr: int,
    baseline_premium: int = BASELINE_PREMIUM_PRICE,
) -> float:
    """
    Calculate Price-to-Security Ratio:
    PSR = (Security Score / 100) / (Device Price / Baseline Premium Price)
    """
    if price_lkr <= 0:
        return 0.0

    score_ratio = security_score / 100.0
    price_ratio = price_lkr / float(baseline_premium)

    if price_ratio <= 0:
        return 0.0

    psr_value = score_ratio / price_ratio
    return round(psr_value, 2)


def generate_recommendation(
    security_score: int,
    risk_level: str,
    findings: list[dict[str, Any]],
    price_lkr: int,
    psr: float,
) -> dict[str, Any]:
    """
    Generate actionable recommendation based on security score, high severity findings and PSR.
    Important rule: Do not let cheap price mask critical findings.
    """
    high_count = sum(
        1 for f in findings
        if (f.get("severity") or f.get("level", "")).strip().lower() in ["high", "critical"]
    )

    if security_score >= 80 and high_count == 0:
        category = "Recommended"
        guidance = "The device demonstrates acceptable baseline security with low observed risk."
    elif security_score >= 60 and high_count <= 1:
        category = "Acceptable with precautions"
        guidance = "Usable with configuration hardening, such as changing default passwords and disabling unused services."
    elif security_score >= 40 and high_count <= 2:
        category = "Use only in isolated or non-sensitive environments"
        guidance = "The device contains notable security flaws. Confine use to guest or isolated IoT VLANs."
    elif high_count >= 3 or security_score < 40:
        category = "Avoid for sensitive networks"
        guidance = "Multiple severe vulnerabilities identified (such as hardcoded credentials or exposed services). Do not connect to banking, work or sensitive corporate networks."
    else:
        category = "Avoid"
        guidance = "Severe security compromises present. Device replacement recommended."

    price_verdict = (
        f"At LKR {price_lkr} (PSR: {psr}), the device appears affordable, "
        f"but its low security score ({security_score}/100) presents significant risk."
        if price_lkr < 5000 and security_score < 50
        else f"Price: LKR {price_lkr} with PSR score {psr}."
    )

    mitigations = [
        "Change default administrator passwords immediately upon deployment.",
        "Disable unencrypted services such as Telnet and HTTP where possible.",
        "Isolate repeater devices on a dedicated guest or test VLAN.",
        "Verify firmware update availability from verified vendor sources.",
    ]

    return {
        "category": category,
        "risk_level": risk_level,
        "guidance": guidance,
        "price_verdict": price_verdict,
        "high_findings_count": high_count,
        "mitigations": mitigations,
    }


def evaluate_device_security(
    device_id: str | None = None,
    assessment_id: str | None = None,
    custom_price: int | None = None,
) -> dict[str, Any]:
    """
    Complete scoring and recommendation pipeline for a given device or assessment session.
    """
    findings: list[dict[str, Any]] = []
    target_price = 0
    target_name = device_id or "Custom Device"

    if assessment_id:
        asm = get_assessment_by_id(assessment_id)
        if asm:
            stored_price = asm.get("price_lkr")
            if custom_price is not None and custom_price > 0:
                target_price = custom_price
            elif stored_price is not None and stored_price > 0:
                target_price = stored_price
            target_name = f"{asm.get('id', assessment_id)} ({asm.get('device_id', 'Target-Device')})"
        findings = get_findings_by_assessment_id(assessment_id)
    elif device_id:
        dev = get_device_by_id(device_id)
        if dev:
            stored_price = dev.get("price_lkr")
            if custom_price is not None and custom_price > 0:
                target_price = custom_price
            elif stored_price is not None and stored_price > 0:
                target_price = stored_price
            target_name = dev.get("display_name", device_id)
        findings = get_findings_by_device_id(device_id)
    elif custom_price is not None and custom_price > 0:
        target_price = custom_price

    score_result = calculate_security_score(findings)
    final_score = score_result["final_score"]
    risk_level = determine_risk_level(final_score)
    psr = calculate_psr(final_score, target_price)
    rec = generate_recommendation(final_score, risk_level, findings, target_price, psr)

    severity_counts = count_findings_by_severity(
        device_id=device_id if not assessment_id else None,
        assessment_id=assessment_id,
    )

    return {
        "device_or_assessment": target_name,
        "price_lkr": target_price,
        "findings_count": len(findings),
        "severity_counts": severity_counts,
        "base_score": score_result["base_score"],
        "total_deductions": score_result["total_deductions"],
        "final_score": final_score,
        "risk_level": risk_level,
        "psr": psr,
        "recommendation": rec,
        "deductions_detail": score_result["deductions_detail"],
    }
