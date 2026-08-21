from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .artifacts import detect_magic, entropy, printable_strings, read_prefix, safe_relative, sha256_file
from .detectors import scan_file_text, scan_strings
from .models import AnalysisReport, Finding, InputArtifact, utc_now


TOOL_NAME = "GHOST-FirmwareAnalyzer"
TOOL_VERSION = "3.0.0"


class AnalysisError(Exception):
    pass


def artifact_from_file(path: Path, kind: str) -> InputArtifact:
    if not path.is_file():
        raise AnalysisError(f"Input is not a regular file: {path}")
    stat = path.stat()
    return InputArtifact(path=str(path.resolve()), kind=kind, size_bytes=stat.st_size, sha256=sha256_file(path), magic=detect_magic(read_prefix(path, 512)), analyzed_at=utc_now())


def analyze_file(path: Path, max_bytes: int = 256 * 1024 * 1024) -> AnalysisReport:
    if not path.is_file():
        raise AnalysisError(f"Firmware file does not exist or is not a file: {path}")
    if path.stat().st_size > max_bytes:
        raise AnalysisError(f"Input exceeds configured limit of {max_bytes} bytes: {path}")
    started = utc_now()
    data = path.read_bytes()
    artifact = artifact_from_file(path, "firmware-image")
    strings = printable_strings(data)
    findings = scan_strings(strings, source="firmware-image")
    findings.extend(_binary_metadata_findings(data, artifact))
    return AnalysisReport(tool=TOOL_NAME, version=TOOL_VERSION, mode="static-file", target=str(path.resolve()), started_at=started, completed_at=utc_now(), artifacts=[artifact], findings=_dedup(findings), metadata={"bytes_read": len(data), "printable_string_count": len(strings), "entropy_bits_per_byte": round(entropy(data), 6), "execution_performed": False, "network_access_performed": False})


def analyze_rootfs(root: Path, max_files: int = 100_000, max_file_bytes: int = 16 * 1024 * 1024) -> AnalysisReport:
    if not root.is_dir():
        raise AnalysisError(f"Root filesystem directory does not exist: {root}")
    started = utc_now()
    artifacts: list[InputArtifact] = []
    findings: list[Finding] = []
    scanned_files = 0
    skipped_files = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [directory for directory in directories if not (Path(current) / directory).is_symlink()]
        for filename in files:
            path = Path(current) / filename
            if path.is_symlink() or not path.is_file():
                skipped_files += 1
                continue
            if scanned_files >= max_files:
                skipped_files += 1
                continue
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    skipped_files += 1
                    continue
                artifact = artifact_from_file(path, "rootfs-file")
                artifacts.append(InputArtifact(path=safe_relative(path, root), kind=artifact.kind, size_bytes=artifact.size_bytes, sha256=artifact.sha256, magic=artifact.magic, analyzed_at=artifact.analyzed_at))
                findings.extend(scan_file_text(path, root))
                scanned_files += 1
            except (OSError, UnicodeError):
                skipped_files += 1
    return AnalysisReport(tool=TOOL_NAME, version=TOOL_VERSION, mode="static-rootfs", target=str(root.resolve()), started_at=started, completed_at=utc_now(), artifacts=artifacts, findings=_dedup(findings), metadata={"files_scanned": scanned_files, "files_skipped": skipped_files, "execution_performed": False, "network_access_performed": False, "symlinks_followed": False})


def _binary_metadata_findings(data: bytes, artifact: InputArtifact) -> list[Finding]:
    findings: list[Finding] = []
    magic = artifact.magic or "unknown"
    if magic == "PE/COFF executable":
        findings.append(Finding(rule_id="FW-FMT-PE", title="Windows PE payload embedded", severity="medium", confidence="high", description="The input begins with a PE/COFF signature.", evidence="MZ", source="file-signature", remediation="Confirm that a PE payload is expected and validate its provenance and signature.", tags=("firmware", "format")))
    if magic and "ELF" in magic and b"GNU C Library" in data:
        findings.append(Finding(rule_id="FW-ELF-GLIBC", title="ELF image references glibc", severity="info", confidence="medium", description="The binary contains a glibc marker; this is an inventory observation, not a vulnerability claim.", evidence="GNU C Library", source="binary-content", remediation="Record the component version and compare it with the vendor support baseline.", tags=("firmware", "inventory")))
    return findings


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.evidence, finding.location)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
