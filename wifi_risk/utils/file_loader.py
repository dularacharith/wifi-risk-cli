import json
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[2]


def load_json(relative_path: str) -> Any:
    file_path = BASE_DIR / relative_path

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(relative_path: str, data: Any) -> None:
    file_path = BASE_DIR / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)