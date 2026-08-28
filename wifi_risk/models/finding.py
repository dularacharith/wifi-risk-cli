from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    id: str
    device_id: str
    title: str
    category: str
    severity: str
    status: str = "Confirmed"
    assessment_id: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    module: str = ""
    date_observed: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            id=data.get("id", ""),
            device_id=data.get("device_id", ""),
            title=data.get("title", ""),
            category=data.get("category", ""),
            severity=data.get("severity", "Informational"),
            status=data.get("status", "Confirmed"),
            assessment_id=data.get("assessment_id", ""),
            evidence=data.get("evidence", ""),
            impact=data.get("impact", ""),
            recommendation=data.get("recommendation", ""),
            module=data.get("module", ""),
            date_observed=data.get("date_observed", ""),
        )