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
    level: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d.get("level"):
            d["level"] = d.get("severity", "Informational")
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        sev = data.get("severity") or data.get("level") or "Informational"
        lvl = data.get("level") or sev
        return cls(
            id=data.get("id", ""),
            device_id=data.get("device_id", ""),
            title=data.get("title", ""),
            category=data.get("category", ""),
            severity=sev,
            status=data.get("status", "Confirmed"),
            assessment_id=data.get("assessment_id", ""),
            evidence=data.get("evidence", ""),
            impact=data.get("impact", ""),
            recommendation=data.get("recommendation", ""),
            module=data.get("module", ""),
            date_observed=data.get("date_observed", ""),
            level=lvl,
        )