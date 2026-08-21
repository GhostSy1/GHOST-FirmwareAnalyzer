from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def append_record(path: Path, report_digest: str, target: str, finding_count: int) -> dict[str, Any]:
    previous_hash = "0" * 64
    if path.exists() and path.stat().st_size:
        last_line = path.read_text(encoding="utf-8").splitlines()[-1]
        previous = json.loads(last_line)
        previous_hash = previous["record_hash"]
    body = {"target": target, "report_sha256": report_digest, "finding_count": finding_count, "previous_hash": previous_hash}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record_hash = hashlib.sha256(canonical).hexdigest()
    record = {**body, "record_hash": record_hash}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def verify(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return True, "ledger does not exist"
    expected_previous = "0" * 64
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        record = json.loads(line)
        body = {key: record[key] for key in ("target", "report_sha256", "finding_count", "previous_hash")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_hash = hashlib.sha256(canonical).hexdigest()
        if record.get("previous_hash") != expected_previous:
            return False, f"previous hash mismatch at line {line_number}"
        if record.get("record_hash") != expected_hash:
            return False, f"record hash mismatch at line {line_number}"
        expected_previous = record["record_hash"]
    return True, "ledger verified"
