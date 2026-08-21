from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from .analyzer import AnalysisError, analyze_file, analyze_rootfs
from .ledger import append_record, verify
from .reporting import write_csv, write_json, write_sarif

BANNER = r"""
   _____ _   _  ____  ____ _____
  / ____| | | |/ __ \ / __ \_   _|
 | |  __| |_| | |  | | |  | || |
 | | |_ |  _  | |  | | |  | || |
 | |__| | | | | |__| | |__| || |_
  \_____|_| |_|\____/ \____/_____|

 GHOST-FirmwareAnalyzer 3.0.0
 Static firmware and embedded-system evidence analyzer
"""


def clear_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghost-firmware-analyzer", description="Analyze firmware images or extracted root filesystems without executing their contents.")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--firmware", type=Path, help="Path to a firmware image or binary file")
    target.add_argument("--rootfs", type=Path, help="Path to an already extracted root filesystem directory")
    parser.add_argument("--json", type=Path, default=Path("ghost-firmware-report.json"), help="Write the normalized JSON report")
    parser.add_argument("--csv", type=Path, help="Write findings as CSV")
    parser.add_argument("--sarif", type=Path, help="Write SARIF 2.1.0 results")
    parser.add_argument("--ledger", type=Path, default=Path("ghost-audit-ledger.jsonl"), help="Append the report provenance record")
    parser.add_argument("--max-files", type=int, default=100_000, help="Maximum rootfs files to inspect")
    parser.add_argument("--max-file-bytes", type=int, default=16 * 1024 * 1024, help="Maximum size of an individual rootfs file")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024, help="Maximum firmware image size")
    parser.add_argument("--verify-ledger", action="store_true", help="Verify an existing ledger and exit")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear the terminal before printing the banner")
    return parser


def interactive_target() -> tuple[Path | None, Path | None]:
    print("اختر نوع الإدخال: 1) firmware image  2) extracted rootfs")
    choice = input("الاختيار [1/2]: ").strip()
    target = Path(input("المسار: ").strip()).expanduser()
    return (target, None) if choice == "1" else (None, target)


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_clear:
        clear_screen()
    print(BANNER)
    if args.verify_ledger:
        valid, message = verify(args.ledger)
        print(("[+] " if valid else "[-] ") + message)
        return 0 if valid else 2
    firmware = args.firmware
    rootfs = args.rootfs
    if firmware is None and rootfs is None:
        if not sys.stdin.isatty():
            parser.error("one of --firmware or --rootfs is required in non-interactive mode")
        firmware, rootfs = interactive_target()
    try:
        report = analyze_file(firmware, max_bytes=args.max_bytes) if firmware else analyze_rootfs(rootfs, max_files=args.max_files, max_file_bytes=args.max_file_bytes)
    except AnalysisError as error:
        print(f"[-] {error}", file=sys.stderr)
        return 2
    args.json.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, args.json)
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        write_csv(report, args.csv)
    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        write_sarif(report, args.sarif)
    report_digest = hashlib.sha256(args.json.read_bytes()).hexdigest()
    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    record = append_record(args.ledger, report_digest, report.target, len(report.findings))
    print(f"[+] Target: {report.target}")
    print(f"[+] Mode: {report.mode} | Findings: {len(report.findings)} | Risk score: {report.risk_score()}/100")
    print(f"[+] JSON report: {args.json}")
    if args.csv:
        print(f"[+] CSV report: {args.csv}")
    if args.sarif:
        print(f"[+] SARIF report: {args.sarif}")
    print(f"[+] Ledger record: {record['record_hash']}")
    return 0
