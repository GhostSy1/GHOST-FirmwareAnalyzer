from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class EnhancedFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    remediation: str

    to_dict = lambda self: asdict(self)


def export_report_json(findings: list[EnhancedFinding], target: str) -> str:
    payload = {
        "target": target,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings]
    }
    return json.dumps(payload, indent=2)
