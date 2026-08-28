import platform
import re
import socket
import subprocess
from typing import Any


def list_all_interfaces() -> list[dict[str, Any]]:
    """
    Enumerate all available network interfaces, their local IPv4 addresses, and default gateways.
    Supports Windows, Linux, and macOS.
    """
    system_name = platform.system().lower()
    interfaces: list[dict[str, Any]] = []

    if "windows" in system_name:
        try:
            ipconfig_output = subprocess.check_output(
                ["ipconfig", "/all"],
                text=True,
                errors="ignore",
                timeout=4,
            )

            # Split by adapter sections
            sections = re.split(r"(?:Wireless LAN adapter|Ethernet adapter|Unknown adapter)\s+([^:\r\n]+):", ipconfig_output)
            if len(sections) > 1:
                for i in range(1, len(sections), 2):
                    iface_name = sections[i].strip()
                    body = sections[i + 1]

                    # Filter out disconnected or inactive adapters
                    if "Media disconnected" in body or "Media State . . . . . . . . . . . : Media disconnected" in body:
                        continue

                    ip_match = re.search(r"IPv4 Address[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)
                    gw_match = re.search(r"Default Gateway[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)
                    mask_match = re.search(r"Subnet Mask[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)

                    if ip_match:
                        local_ip = ip_match.group(1).strip()
                        gateway_ip = gw_match.group(1).strip() if (gw_match and gw_match.group(1).strip() != "0.0.0.0") else None

                        # If no explicit gateway, infer subnet .1
                        if not gateway_ip and local_ip:
                            octs = local_ip.split(".")
                            if len(octs) == 4:
                                gateway_ip = f"{octs[0]}.{octs[1]}.{octs[2]}.1"

                        interfaces.append(
                            {
                                "name": iface_name,
                                "local_ip": local_ip,
                                "gateway_ip": gateway_ip or "192.168.11.1",
                                "subnet_mask": mask_match.group(1).strip() if mask_match else "255.255.255.0",
                                "is_default": False,
                            }
                        )
        except Exception:
            pass

    elif "linux" in system_name:
        try:
            # 1. Get routes
            routes_out = subprocess.check_output(["ip", "route", "show"], text=True, errors="ignore", timeout=3)
            default_iface = None
            default_gw = None
            def_match = re.search(r"default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) dev ([^\s]+)", routes_out)
            if def_match:
                default_gw = def_match.group(1).strip()
                default_iface = def_match.group(2).strip()

            # 2. Get IP addresses per interface
            addr_out = subprocess.check_output(["ip", "-o", "addr", "show"], text=True, errors="ignore", timeout=3)
            for line in addr_out.splitlines():
                m = re.search(r"^\d+:\s+([^\s]+)\s+inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(\d+)", line.strip())
                if m:
                    iface = m.group(1)
                    local_ip = m.group(2)
                    if local_ip.startswith("127."):
                        continue

                    # Find gateway for this interface
                    gw_for_iface = None
                    if iface == default_iface and default_gw:
                        gw_for_iface = default_gw
                    else:
                        # Subnet heuristic
                        octs = local_ip.split(".")
                        if len(octs) == 4:
                            gw_for_iface = f"{octs[0]}.{octs[1]}.{octs[2]}.1"

                    interfaces.append(
                        {
                            "name": iface,
                            "local_ip": local_ip,
                            "gateway_ip": gw_for_iface or "192.168.11.1",
                            "subnet_mask": m.group(3),
                            "is_default": (iface == default_iface),
                        }
                    )
        except Exception:
            pass

    elif "darwin" in system_name:
        try:
            netstat_out = subprocess.check_output(["netstat", "-nr", "-f", "inet"], text=True, errors="ignore", timeout=3)
            def_match = re.search(r"^default\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+UGSc\s+([^\s]+)", netstat_out, re.MULTILINE)
            default_gw = def_match.group(1).strip() if def_match else None
            default_iface = def_match.group(2).strip() if def_match else None

            ifconfig_out = subprocess.check_output(["ifconfig"], text=True, errors="ignore", timeout=3)
            sections = re.split(r"^([a-zA-Z0-9]+):", ifconfig_out, flags=re.MULTILINE)
            if len(sections) > 1:
                for i in range(1, len(sections), 2):
                    iface_name = sections[i].strip()
                    body = sections[i + 1]
                    ip_match = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", body)
                    if ip_match:
                        local_ip = ip_match.group(1).strip()
                        if not local_ip.startswith("127."):
                            gw = default_gw if iface_name == default_iface else None
                            if not gw:
                                octs = local_ip.split(".")
                                gw = f"{octs[0]}.{octs[1]}.{octs[2]}.1"
                            interfaces.append(
                                {
                                    "name": iface_name,
                                    "local_ip": local_ip,
                                    "gateway_ip": gw,
                                    "subnet_mask": "255.255.255.0",
                                    "is_default": (iface_name == default_iface),
                                }
                            )
        except Exception:
            pass

    # Ensure at least default gateway detection exists if enumeration returned empty
    if not interfaces:
        single = detect_default_gateway()
        interfaces.append(
            {
                "name": single["interface_name"],
                "local_ip": single["local_ip"],
                "gateway_ip": single["gateway_ip"],
                "subnet_mask": "255.255.255.0",
                "is_default": True,
            }
        )

    # Mark the primary default interface
    has_default = any(item.get("is_default") for item in interfaces)
    if not has_default and interfaces:
        interfaces[0]["is_default"] = True

    return interfaces


def detect_default_gateway(fallback: str = "192.168.11.1") -> dict[str, Any]:
    """
    Automatically detect the active network interface and default gateway IP address.
    Supports Windows, Linux and macOS.
    """
    system_name = platform.system().lower()
    gateway_ip = None
    interface_name = None
    local_ip = None
    detection_method = "fallback"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        local_ip = None

    if "windows" in system_name:
        try:
            ipconfig_output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                errors="ignore",
                timeout=3,
            )

            adapter_sections = re.split(r"(?:Wireless LAN adapter|Ethernet adapter)\s+([^:\r\n]+):", ipconfig_output)
            if len(adapter_sections) > 1:
                for i in range(1, len(adapter_sections), 2):
                    section_name = adapter_sections[i].strip()
                    section_body = adapter_sections[i + 1]

                    gw_match = re.search(r"Default Gateway[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", section_body)
                    ip_match = re.search(r"IPv4 Address[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", section_body)

                    if gw_match:
                        found_gw = gw_match.group(1).strip()
                        if found_gw != "0.0.0.0":
                            gateway_ip = found_gw
                            interface_name = section_name
                            if ip_match:
                                local_ip = ip_match.group(1).strip()
                            detection_method = "windows_ipconfig"
                            break

            if not gateway_ip:
                gw_match = re.search(r"Default Gateway[ .]*:[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ipconfig_output)
                if gw_match and gw_match.group(1).strip() != "0.0.0.0":
                    gateway_ip = gw_match.group(1).strip()
                    interface_name = "Active Network Adapter"
                    detection_method = "windows_ipconfig_global"
        except Exception:
            pass

    elif "linux" in system_name:
        try:
            route_out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True,
                errors="ignore",
                timeout=3,
            )
            gw_match = re.search(r"default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?: dev ([^\s]+))?", route_out)
            if gw_match:
                gateway_ip = gw_match.group(1).strip()
                interface_name = gw_match.group(2).strip() if gw_match.group(2) else "Default Interface"
                detection_method = "linux_ip_route"
        except Exception:
            try:
                with open("/proc/net/route", "r") as f:
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        if len(fields) >= 3 and fields[1] == "00000000":
                            hex_gw = fields[2]
                            octets = [str(int(hex_gw[i : i + 2], 16)) for i in range(6, -1, -2)]
                            gateway_ip = ".".join(octets)
                            interface_name = fields[0]
                            detection_method = "linux_proc_route"
                            break
            except Exception:
                pass

    elif "darwin" in system_name:
        try:
            route_out = subprocess.check_output(
                ["netstat", "-nr", "-f", "inet"],
                text=True,
                errors="ignore",
                timeout=3,
            )
            gw_match = re.search(r"^default\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+UGSc\s+([^\s]+)", route_out, re.MULTILINE)
            if gw_match:
                gateway_ip = gw_match.group(1).strip()
                interface_name = gw_match.group(2).strip()
                detection_method = "darwin_netstat"
        except Exception:
            pass

    if not gateway_ip and local_ip and local_ip != "127.0.0.1":
        octets = local_ip.split(".")
        if len(octets) == 4:
            gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.1"
            interface_name = interface_name or "Detected Subnet Gateway"
            detection_method = "subnet_heuristic"

    if not gateway_ip:
        gateway_ip = fallback
        interface_name = interface_name or "Default Gateway"
        detection_method = "static_fallback"

    return {
        "gateway_ip": gateway_ip,
        "local_ip": local_ip or "127.0.0.1",
        "interface_name": interface_name or "Active Network Adapter",
        "system": system_name,
        "detection_method": detection_method,
    }


def get_auto_target_ip(fallback: str = "192.168.11.1") -> str:
    """
    Convenience helper returning just the detected gateway IP string.
    """
    result = detect_default_gateway(fallback=fallback)
    return result["gateway_ip"]
