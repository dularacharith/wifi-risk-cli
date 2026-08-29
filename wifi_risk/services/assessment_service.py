from datetime import datetime
from typing import Any

from wifi_risk.models.assessment import Assessment
from wifi_risk.utils.file_loader import load_json, save_json

ASSESSMENTS_FILE = "data/assessments.json"


def get_all_assessments() -> list[dict[str, Any]]:
    try:
        return load_json(ASSESSMENTS_FILE)
    except FileNotFoundError:
        return []


def get_assessment_by_id(assessment_id: str) -> dict[str, Any] | None:
    assessments = get_all_assessments()

    for assessment in assessments:
        if assessment["id"].lower() == assessment_id.lower():
            return assessment

    return None


def generate_next_assessment_id() -> str:
    assessments = get_all_assessments()
    if not assessments:
        return "ASM-001"

    max_num = 0
    for assessment in assessments:
        curr_id = assessment.get("id", "")
        if curr_id.upper().startswith("ASM-"):
            try:
                num = int(curr_id.split("-")[1])
                if num > max_num:
                    max_num = num
            except (IndexError, ValueError):
                continue

    return f"ASM-{max_num + 1:03d}"


def create_assessment(
    device_id: str,
    target_ip: str,
    price_lkr: int,
    notes: str = "",
    metadata: dict[str, Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    assessments = get_all_assessments()
    now_iso = datetime.now().isoformat(timespec="seconds")
    assessment_id = generate_next_assessment_id()

    new_assessment = Assessment(
        id=assessment_id,
        device_id=device_id,
        target_ip=target_ip,
        price_lkr=price_lkr,
        status="Created",
        created_at=now_iso,
        updated_at=now_iso,
        notes=notes,
        metadata=metadata if metadata is not None else {},
        checks=checks if checks is not None else [],
    )

    assessment_dict = new_assessment.to_dict()
    assessments.append(assessment_dict)
    save_json(ASSESSMENTS_FILE, assessments)

    return assessment_dict


def update_assessment(assessment_id: str, updates_dict: dict[str, Any] | None = None, **updates: Any) -> dict[str, Any] | None:
    assessments = get_all_assessments()

    merged_updates: dict[str, Any] = {}
    if updates_dict:
        merged_updates.update(updates_dict)
    merged_updates.update(updates)

    for index, assessment in enumerate(assessments):
        if assessment["id"].lower() == assessment_id.lower():
            for key, value in merged_updates.items():
                if key != "id":
                    assessment[key] = value

            assessment["updated_at"] = datetime.now().isoformat(timespec="seconds")
            assessments[index] = assessment
            save_json(ASSESSMENTS_FILE, assessments)
            return assessment

    return None


def add_assessment_check(assessment_id: str, check_data: dict[str, Any]) -> dict[str, Any] | None:
    assessments = get_all_assessments()

    for index, assessment in enumerate(assessments):
        if assessment["id"].lower() == assessment_id.lower():
            checks = assessment.get("checks", [])
            module_name = check_data.get("module")
            updated = False
            for c_idx, existing_check in enumerate(checks):
                if existing_check.get("module") == module_name:
                    checks[c_idx] = check_data
                    updated = True
                    break
            if not updated:
                checks.append(check_data)

            assessment["checks"] = checks
            assessment["status"] = "In Progress"
            assessment["updated_at"] = datetime.now().isoformat(timespec="seconds")
            assessments[index] = assessment
            save_json(ASSESSMENTS_FILE, assessments)
            return assessment

    return None


def classify_assessment_type(asm: dict[str, Any]) -> str:
    """
    Classify an assessment session into one of three categories:
    - 'quick_scan': Standalone / quick scan session
    - 'full_assessment': Full in-depth multi-layer assessment session
    - 'created': Created / pending session without executed tests
    """
    meta = asm.get("metadata", {})
    scan_type = meta.get("scan_type", "").lower()
    asm_type = meta.get("assessment_type", "").lower()

    if scan_type == "quick_scan" or asm_type == "quick_scan":
        return "quick_scan"
    if scan_type == "full_assessment" or asm_type == "full_assessment":
        return "full_assessment"

    notes = asm.get("notes", "").lower()
    if "quick scan" in notes:
        return "quick_scan"

    checks = asm.get("checks", [])
    status = asm.get("status", "Created")

    if status == "Completed" or len(checks) >= 2 or "direct cli" in notes or "live security assessment" in notes:
        return "full_assessment"

    if status == "Created" and len(checks) == 0:
        return "created"

    if len(checks) > 0:
        return "full_assessment"

    return "created"


def get_assessments_by_category(category: str = "all") -> list[dict[str, Any]]:
    """
    Filter assessments by category: 'all', 'quick_scan', 'full_assessment', or 'created'.
    """
    all_asms = get_all_assessments()
    cat = category.lower().strip()

    if cat in ["all", ""]:
        return all_asms
    return [a for a in all_asms if classify_assessment_type(a) == cat]


def delete_assessment_by_id(assessment_id: str) -> bool:
    """
    Delete a specific assessment session by its ID and clean up associated findings and evidence.
    Returns True if deleted, False if not found.
    """
    import glob
    import os

    assessments = get_all_assessments()
    initial_len = len(assessments)
    filtered = [a for a in assessments if a.get("id", "").lower() != assessment_id.lower()]

    if len(filtered) < initial_len:
        save_json(ASSESSMENTS_FILE, filtered)
        try:
            from wifi_risk.services.finding_service import delete_findings_by_assessment_id

            delete_findings_by_assessment_id(assessment_id)
        except Exception:
            pass

        # Clean up evidence files
        for ev_file in glob.glob(f"data/evidence/{assessment_id}*"):
            try:
                if os.path.exists(ev_file):
                    os.remove(ev_file)
            except Exception:
                pass

        return True
    return False


def delete_assessments_by_ids(assessment_ids: list[str]) -> int:
    """
    Delete multiple assessment sessions and clean up their associated findings and evidence.
    Returns the count of successfully deleted assessments.
    """
    count = 0
    for aid in assessment_ids:
        if delete_assessment_by_id(aid):
            count += 1
    return count


def clear_all_assessments() -> int:
    """
    Clear all assessment sessions from the database and clean up findings and evidence.
    Returns the count of deleted assessments.
    """
    import glob
    import os

    assessments = get_all_assessments()
    count = len(assessments)
    save_json(ASSESSMENTS_FILE, [])

    try:
        from wifi_risk.services.finding_service import FINDINGS_FILE, get_all_findings, save_json

        findings = get_all_findings()
        # Keep only baseline findings (e.g. BASE-*)
        cleaned = [f for f in findings if f.get("assessment_id", "").startswith("BASE-")]
        save_json(FINDINGS_FILE, cleaned)
    except Exception:
        pass

    # Clean up assessment evidence files
    for ev_file in glob.glob("data/evidence/ASM-*"):
        try:
            if os.path.exists(ev_file):
                os.remove(ev_file)
        except Exception:
            pass

    return count

