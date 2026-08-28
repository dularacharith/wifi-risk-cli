from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Assessment:
    id: str
    device_id: str
    target_ip: str
    price_lkr: int
    status: str
    created_at: str
    updated_at: str
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Assessment":
        return cls(
            id=data.get("id", ""),
            device_id=data.get("device_id", ""),
            target_ip=data.get("target_ip", ""),
            price_lkr=int(data.get("price_lkr", 0)),
            status=data.get("status", "Created"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            checks=data.get("checks", []),
        )
