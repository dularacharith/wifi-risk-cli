from typing import Any
from wifi_risk.utils.file_loader import load_json


def get_all_devices() -> list[dict[str, Any]]:
    return load_json("data/devices.json")


def get_device_by_id(device_id: str) -> dict[str, Any] | None:
    devices = get_all_devices()

    for device in devices:
        if device["id"].lower() == device_id.lower():
            return device

    return None