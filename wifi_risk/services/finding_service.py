from typing import Any

from wifi_risk.utils.file_loader import load_json


def get_all_findings() -> list[dict[str, Any]]:
    return load_json("data/findings.json")


def get_findings_by_device_id(device_id: str) -> list[dict[str, Any]]:
    findings = get_all_findings()

    matched_findings = []

    for finding in findings:
        if finding["device_id"].lower() == device_id.lower():
            matched_findings.append(finding)

    return matched_findings


def count_findings_by_severity(device_id: str) -> dict[str, int]:
    findings = get_findings_by_device_id(device_id)

    counts = {
        "High": 0,
        "Medium": 0,
        "Low-Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:
        severity = finding["severity"]

        if severity in counts:
            counts[severity] += 1
        else:
            counts[severity] = 1

    return counts