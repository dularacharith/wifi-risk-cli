from typing import Any

from wifi_risk.models.finding import Finding
from wifi_risk.utils.file_loader import load_json, save_json

FINDINGS_FILE = "data/findings.json"


def get_all_findings() -> list[dict[str, Any]]:
    """
    Retrieve all findings from persistent storage.
    """
    try:
        findings = load_json(FINDINGS_FILE)
        for f in findings:
            if not f.get("level") and f.get("severity"):
                f["level"] = f["severity"]
            elif not f.get("severity") and f.get("level"):
                f["severity"] = f["level"]
        return findings
    except FileNotFoundError:
        return []


def get_finding_by_id(finding_id: str) -> dict[str, Any] | None:
    """
    Retrieve a specific finding by its unique identifier.
    """
    findings = get_all_findings()
    for finding in findings:
        if finding.get("id", "").lower() == finding_id.lower():
            return finding
    return None


def get_findings_by_device_id(device_id: str) -> list[dict[str, Any]]:
    """
    Retrieve all findings associated with a given device ID.
    """
    findings = get_all_findings()
    return [f for f in findings if f.get("device_id", "").lower() == device_id.lower()]


def get_findings_by_assessment_id(assessment_id: str) -> list[dict[str, Any]]:
    """
    Retrieve all findings generated during a specific assessment session.
    Ensures findings strictly belong to the assessment and match its active device.
    If the assessment has no checks executed yet (checks == []), returns [] (clean baseline).
    """
    from wifi_risk.services.assessment_service import get_assessment_by_id

    asm = get_assessment_by_id(assessment_id)
    if not asm:
        return []

    # If no checks were run or recorded for this assessment, return 0 findings
    asm_checks = asm.get("checks", [])
    if not asm_checks:
        return []

    asm_device_id = asm.get("device_id", "").strip().lower()
    findings = get_all_findings()
    return [
        f for f in findings
        if f.get("assessment_id", "").lower() == assessment_id.lower()
        and (not asm_device_id or f.get("device_id", "").strip().lower() == asm_device_id)
    ]


def delete_findings_by_assessment_id(assessment_id: str) -> int:
    """
    Remove all stored findings associated with a deleted assessment session.
    """
    findings = get_all_findings()
    initial_len = len(findings)
    filtered = [f for f in findings if f.get("assessment_id", "").lower() != assessment_id.lower()]
    if len(filtered) < initial_len:
        save_json(FINDINGS_FILE, filtered)
    return initial_len - len(filtered)


def save_finding(finding_input: dict[str, Any] | Finding) -> dict[str, Any]:
    """
    Add a new finding or update an existing finding in the storage database.
    """
    findings = get_all_findings()

    if isinstance(finding_input, Finding):
        finding_dict = finding_input.to_dict()
    else:
        finding_dict = Finding.from_dict(finding_input).to_dict()

    target_id = finding_dict.get("id", "")
    existing_index = None

    for idx, f in enumerate(findings):
        if f.get("id", "").lower() == target_id.lower():
            existing_index = idx
            break

    if existing_index is not None:
        findings[existing_index] = finding_dict
    else:
        findings.append(finding_dict)

    save_json(FINDINGS_FILE, findings)
    return finding_dict


def import_findings(findings_list: list[dict[str, Any]]) -> int:
    """
    Batch import findings from assessment modules, avoiding duplicates.
    """
    saved_count = 0
    for finding_data in findings_list:
        save_finding(finding_data)
        saved_count += 1
    return saved_count


def filter_findings(
    device_id: str | None = None,
    assessment_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    module: str | None = None,
) -> list[dict[str, Any]]:
    """
    Filter stored findings by multiple criteria.
    """
    findings = get_all_findings()
    filtered: list[dict[str, Any]] = []

    for f in findings:
        if device_id and f.get("device_id", "").lower() != device_id.lower():
            continue
        if assessment_id and f.get("assessment_id", "").lower() != assessment_id.lower():
            continue
        if severity and (f.get("severity") or f.get("level", "")).strip().lower() != severity.strip().lower():
            continue
        if status and f.get("status", "").lower() != status.lower():
            continue
        if category and category.lower() not in f.get("category", "").lower():
            continue
        if module and module.lower() not in f.get("module", "").lower():
            continue
        filtered.append(f)

    return filtered


def count_findings_by_severity(
    device_id: str | None = None,
    assessment_id: str | None = None,
) -> dict[str, int]:
    """
    Count findings grouped by severity for a device or assessment.
    """
    if assessment_id:
        findings = get_findings_by_assessment_id(assessment_id)
    elif device_id:
        findings = get_findings_by_device_id(device_id)
    else:
        findings = get_all_findings()

    counts = {
        "High": 0,
        "Medium": 0,
        "Low-Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:
        sev = finding.get("severity") or finding.get("level") or "Informational"
        matched = False
        for k in counts:
            if k.lower() == sev.strip().lower():
                counts[k] += 1
                matched = True
                break
        if not matched:
            sev_norm = sev.strip().lower()
            if "low-medium" in sev_norm:
                counts["Low-Medium"] += 1
            elif "medium" in sev_norm:
                counts["Medium"] += 1
            elif "high" in sev_norm or "critical" in sev_norm:
                counts["High"] += 1
            elif "low" in sev_norm:
                counts["Low"] += 1
            else:
                counts["Informational"] += 1

    return counts