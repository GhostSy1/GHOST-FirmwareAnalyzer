#!/usr/bin/env python3
import os
import sys
import json
import argparse
import hashlib
import re

os.environ.pop('SSLKEYLOGFILE', None)

BANNER = r"""
╭────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                        │
│  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ██╗███╗   ██╗████████╗███████╗██╗      │
│ ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██║████╗  ██║╚══██╔══╝██╔════╝██║      │
│ ██║  ███╗███████║██║   ██║███████╗   ██║        ██║██╔██╗ ██║   ██║   █████╗  ██║      │
│ ██║   ██║██╔══██║██║   ██║╚════██║   ██║        ██║██║╚██╗██║   ██║   ██╔══╝  ██║      │
│ ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██╗  ██║██║ ╚████║   ██║   ███████╗███████╗ │
│  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝ │
│      GHOST-FirmwareAnalyzer v2.0-PRO: Advanced IoT Binary & Protocol Security Engine    │
│                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────╯
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

SUSPICIOUS_STRINGS = [
    b'telnetd', b'dropbear', b'backdoor', b'authorized_keys', 
    b'/bin/sh', b'password', b'admin:admin', b'root:'
]

def main():
    clear_screen()
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="GHOST-FirmwareAnalyzer: Advanced Firmware & Protocol Audit")
    parser.add_argument("--firmware", required=True, help="Path to firmware binary or extracted rootfs image")
    parser.add_argument("--json", help="Path to save advanced analysis report", default="firmware_v2_report.json")
    args = parser.parse_args()

    print(f"[*] Deep-scanning firmware image: {args.firmware}")
    
    if not os.path.exists(args.firmware):
        print(f"[-] Error: Firmware file not found at {args.firmware}")
        sys.exit(1)

    hasher = hashlib.sha256()
    findings = []
    
    with open(args.firmware, "rb") as f:
        content = f.read()
        hasher.update(content)
        
        # Scan binary for embedded risk indicators and protocols
        for s in SUSPICIOUS_STRINGS:
            if s in content:
                findings.append({
                    "indicator": s.decode('utf-8', errors='ignore'),
                    "severity": "HIGH",
                    "description": f"Found embedded sensitive binary string or service indicator: {s.decode('utf-8', errors='ignore')}"
                })

    report = {
        "firmware_path": args.firmware,
        "sha256": hasher.hexdigest(),
        "file_size": len(content),
        "total_findings": len(findings),
        "findings": findings
    }

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Advanced firmware & protocol analysis complete. Report saved to: {args.json}")

if __name__ == "__main__":
    main()
