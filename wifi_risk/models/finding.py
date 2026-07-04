from dataclasses import dataclass


@dataclass
class Finding:
    id: str
    device_id: str
    title: str
    category: str
    severity: str
    status: str
    impact: str
    recommendation: str