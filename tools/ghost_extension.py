#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

TOOL = "GHOST-FirmwareAnalyzer"
VERSION = "1.0.0"
PROFILE = "Firmware and extracted root filesystem inventory"
RULES = [('FW-SERVICE', 'telnetd|dropbear|rpcd|gdbserver'), ('FW-PROTOCOL', 'mqtt|tftp|http|AF_PACKET|SOCK_RAW'), ('FW-DEBUG', 'jtag|swd|debug[_ -]?enable|secure[_ -]?boot')]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def evidence(value: str, redact: bool) -> str:
    value = value.strip().replace("\x00", "")[:240]
    if redact:
        return re.sub(r"(?i)(api[_-]?key|access[_-]?token|bearer|password|secret|private[_ -]?key)\s*[:=]?\s*[^\s,;]+", r"\1=[REDACTED]", value)
    return value


def scan_text(path: Path, text: str, redact: bool) -> list[dict]:
    results = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule_id, pattern in RULES:
            if re.search(pattern, line, re.I):
                results.append({"rule_id": rule_id, "severity": "medium", "confidence": "low", "title": f"{rule_id} indicator", "description": f"An observable {rule_id} marker was found in supplied input.", "evidence": evidence(line, redact), "source": "local-input", "location": f"{path}:{line_no}", "remediation": "Validate the observation against the source system and documented policy."})
    return results


def analyze(target: Path) -> dict:
    files = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file() and not p.is_symlink())
    findings = []
    artifacts = []
    for path in files[:100000]:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        rel = str(path.resolve())
        artifacts.append({"path": rel, "size_bytes": len(data), "sha256": digest(path)})
        text = data.decode("utf-8", errors="ignore")
        findings.extend(scan_text(path, text, TOOL == "GHOST-SecretsScanner"))
    return {"schema_version": "1.0.0", "tool": TOOL, "version": VERSION, "profile": PROFILE, "target": str(target.resolve()), "artifacts": artifacts, "findings": findings, "metadata": {"files_considered": len(artifacts), "execution_performed": False, "network_access_performed": False, "external_tools_invoked": False}}


def write_sarif(report: dict, path: Path) -> None:
    results = []
    for finding in report["findings"]:
        results.append({"ruleId": finding["rule_id"], "level": "warning", "message": {"text": finding["description"] + " Evidence: " + finding["evidence"]}, "properties": {"confidence": finding["confidence"], "source": finding["source"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["location"]}}}]})
    payload = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION}}, "results": results}]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{TOOL}: {PROFILE}. Reads supplied files only; never executes or connects to targets.")
    parser.add_argument("--input", type=Path, required=True, help="File or directory containing operator-supplied evidence")
    parser.add_argument("--output", type=Path, default=Path("extension-report.json"))
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--sarif", type=Path)
    args = parser.parse_args()
    if not args.input.exists():
        parser.error(f"input does not exist: {args.input}")
    report = analyze(args.input)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["rule_id", "severity", "confidence", "title", "description", "evidence", "source", "location", "remediation"])
            writer.writeheader()
            writer.writerows(report["findings"])
    if args.sarif:
        write_sarif(report, args.sarif)
    print(json.dumps({"tool": TOOL, "profile": PROFILE, "files": len(report["artifacts"]), "findings": len(report["findings"]), "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
