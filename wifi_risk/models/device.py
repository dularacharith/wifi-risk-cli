from dataclasses import dataclass


@dataclass
class Device:
    id: str
    display_name: str
    brand: str
    model: str
    firmware_version: str
    mac_vendor: str
    price_lkr: int
    purchase_source: str
    security_score: int
    risk_level: str
    recommendation: str
    summary: str