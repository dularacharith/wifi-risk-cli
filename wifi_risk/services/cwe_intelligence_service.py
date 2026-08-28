import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

CWE_CATALOG_FILE = "data/cwe_catalog.json"


def normalize_cwe_id(raw_id: str) -> str:
    """
    Normalize user inputs like '345', 'cwe-345', 'CWE345' into 'CWE-345'.
    """
    cleaned = raw_id.strip().upper()
    match = re.search(r"(?:CWE[-_]?)?(\d+)", cleaned)
    if match:
        return f"CWE-{match.group(1)}"
    return cleaned


def extract_cwes_from_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Extract unique CWE identifiers and their mapped finding titles from a list of findings or alerts.
    """
    cwe_map: dict[str, list[str]] = {}
    cwe_regex = re.compile(r"CWE[-_]?(\d+)", re.IGNORECASE)

    for item in items:
        title = item.get("title", "") or item.get("description", "")
        cwe_field = item.get("cwe", "")
        combined = f"{cwe_field} {title} {item.get('impact', '')}"
        matches = cwe_regex.findall(combined)
        for m in matches:
            norm_id = f"CWE-{m}"
            if norm_id not in cwe_map:
                cwe_map[norm_id] = []
            if title and title not in cwe_map[norm_id]:
                cwe_map[norm_id].append(title)

    result = []
    catalog = load_cwe_catalog()
    for cwe_id, titles in cwe_map.items():
        name = catalog.get(cwe_id, {}).get("name", "Vulnerability Weakness")
        result.append({
            "cwe_id": cwe_id,
            "name": name,
            "titles": titles,
            "in_local_catalog": cwe_id in catalog,
        })
    return result


def load_cwe_catalog() -> dict[str, Any]:
    """
    Load the local MITRE CWE taxonomy knowledge base.
    """
    path = Path(CWE_CATALOG_FILE)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cwe_catalog(catalog: dict[str, Any]) -> None:
    """
    Save the updated CWE catalog to disk.
    """
    path = Path(CWE_CATALOG_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)


def fetch_live_mitre_cwe(cwe_id: str, timeout: float = 8.0) -> Optional[dict[str, Any]]:
    """
    Fetch live official CWE definition from MITRE Corporation (cwe.mitre.org).
    """
    match = re.search(r"CWE-(\d+)", cwe_id)
    if not match:
        return None
    cwe_num = match.group(1)
    url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

    try:
        import requests
        from bs4 import BeautifulSoup

        headers = {"User-Agent": "WiFiRisk-Security-Scanner/1.0 (KIU Cybersecurity Research)"}
        resp = requests.get(url, timeout=timeout, headers=headers)
        if resp.status_code != 200:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")

        # 1. Parse Title
        title = ""
        h2 = soup.find("h2")
        if h2:
            title_text = h2.get_text(strip=True)
            # Remove prefix like 'CWE-345:'
            if ":" in title_text:
                title = title_text.split(":", 1)[1].strip()
            else:
                title = title_text

        # 2. Parse Description
        description = ""
        desc_div = soup.find("div", id=re.compile(r"^Description_\d+")) or soup.find("div", {"id": "Description"})
        if desc_div:
            txt = desc_div.get_text(" ", strip=True)
            if txt.lower().startswith("description"):
                txt = txt[len("description"):].strip()
            description = txt

        # 3. Parse Abstraction
        abstraction = "Weakness"
        meta_div = soup.find("div", {"id": "CWEDefinition"}) or soup
        if "Class" in meta_div.get_text():
            abstraction = "Class Weakness"
        elif "Base" in meta_div.get_text():
            abstraction = "Base Weakness"
        elif "Variant" in meta_div.get_text():
            abstraction = "Variant Weakness"

        if not title and not description:
            return None

        return {
            "id": f"CWE-{cwe_num}",
            "name": title or f"Weakness {cwe_num}",
            "abstraction": abstraction,
            "status": "Active (Live MITRE Feed)",
            "description": description or "Official description available at MITRE.",
            "threat_scenarios": [
                f"Observed technical exposure matching MITRE CWE-{cwe_num} standards.",
                "Potential vulnerability exploitation in IoT and embedded network routers."
            ],
            "affected_components": ["Embedded Network Services", "Web & Firmware Interfaces"],
            "mitigation": "Follow standard MITRE remediation guidelines and vendor security best practices.",
            "related_cves": [],
            "mitre_url": url,
            "fetched_at": datetime.now().isoformat(timespec="seconds"),
        }
    except Exception:
        return None


def query_cwe_intelligence(raw_input: str, force_online: bool = False) -> dict[str, Any]:
    """
    Query CWE intelligence using local knowledge catalog with live online fallback to MITRE.
    """
    cwe_id = normalize_cwe_id(raw_input)
    catalog = load_cwe_catalog()

    # If already in catalog and not forced online
    if not force_online and cwe_id in catalog:
        data = catalog[cwe_id]
        data["source"] = "local_catalog"
        data["success"] = True
        return data

    # Attempt live query to MITRE online
    live_data = fetch_live_mitre_cwe(cwe_id)
    if live_data:
        # Merge with existing catalog data if available to keep rich threat scenarios
        if cwe_id in catalog:
            cached = catalog[cwe_id]
            live_data["threat_scenarios"] = cached.get("threat_scenarios", live_data["threat_scenarios"])
            live_data["affected_components"] = cached.get("affected_components", live_data["affected_components"])
            live_data["mitigation"] = cached.get("mitigation", live_data["mitigation"])
            live_data["related_cves"] = cached.get("related_cves", live_data["related_cves"])

        catalog[cwe_id] = live_data
        save_cwe_catalog(catalog)

        live_data["source"] = "live_mitre_online"
        live_data["success"] = True
        return live_data

    # Fallback to local catalog if live query failed
    if cwe_id in catalog:
        data = catalog[cwe_id]
        data["source"] = "local_catalog (offline fallback)"
        data["success"] = True
        return data

    return {
        "id": cwe_id,
        "name": "Unknown / Custom Weakness",
        "success": False,
        "source": "not_found",
        "description": f"No official MITRE definition found for '{raw_input}'.",
        "threat_scenarios": [],
        "affected_components": [],
        "mitigation": "Validate standard defensive coding and firmware hardening measures.",
        "related_cves": [],
        "mitre_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
    }


def search_cwe_catalog(keyword: str) -> list[dict[str, Any]]:
    """
    Search local CWE catalog across titles, descriptions, threat scenarios, and components.
    """
    catalog = load_cwe_catalog()
    kw = keyword.strip().lower()
    matches = []

    for cwe_id, entry in catalog.items():
        search_blob = " ".join([
            entry.get("id", ""),
            entry.get("name", ""),
            entry.get("description", ""),
            " ".join(entry.get("threat_scenarios", [])),
            " ".join(entry.get("affected_components", [])),
            entry.get("mitigation", ""),
        ]).lower()

        if kw in search_blob:
            matches.append(entry)

    return matches


def sync_all_catalog_cwes() -> dict[str, Any]:
    """
    Synchronize all registered CWEs against live MITRE definitions.
    """
    catalog = load_cwe_catalog()
    synced = 0
    failed = 0

    for cwe_id in list(catalog.keys()):
        live = fetch_live_mitre_cwe(cwe_id)
        if live:
            catalog[cwe_id]["name"] = live.get("name", catalog[cwe_id].get("name"))
            catalog[cwe_id]["description"] = live.get("description", catalog[cwe_id].get("description"))
            catalog[cwe_id]["abstraction"] = live.get("abstraction", catalog[cwe_id].get("abstraction"))
            catalog[cwe_id]["last_synced"] = datetime.now().isoformat(timespec="seconds")
            synced += 1
        else:
            failed += 1

    save_cwe_catalog(catalog)
    return {
        "total": len(catalog),
        "synced": synced,
        "failed": failed,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
