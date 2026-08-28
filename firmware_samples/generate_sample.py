import os
from pathlib import Path

out_dir = Path("firmware_samples")
out_dir.mkdir(parents=True, exist_ok=True)

sample_fw_path = out_dir / "wr001_sample_firmware.bin"

# Build mock firmware bytes with TRX header and embedded strings
data = bytearray()
data.extend(b"HDR0") # TRX magic header
data.extend(b"\x00" * 28) # padding
data.extend(b"Linux kernel 2.6.36 (root@buildserver) MIPS R3000\n")
data.extend(b"System initialization: /etc/init.d/rcS\n")
data.extend(b"Starting services: telnetd -l /bin/sh &\n")
data.extend(b"Starting web server: httpd -p 80 &\n")
data.extend(b"Starting dns daemon: dnsmasq -C /etc/dnsmasq.conf\n")
data.extend(b"Default configuration: username=admin password=admin pcPassword=admin\n")
data.extend(b"Firmware build: 1.0.1.2-urant-p1R-auto\n")
data.extend(b"Vendor: C&S Technology / Urant\n")
data.extend(b"\x00" * 512)

with open(sample_fw_path, "wb") as f:
    f.write(data)

print(f"Created sample firmware file at: {sample_fw_path} ({len(data)} bytes)")
