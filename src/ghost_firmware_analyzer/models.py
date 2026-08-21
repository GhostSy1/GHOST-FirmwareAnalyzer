from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence: str
    source: str
    location: str | None = None
    remediation: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["tags"] = list(self.tags)
        return result


@dataclass(frozen=True)
class InputArtifact:
    path: str
    kind: str
    size_bytes: int
    sha256: str
    magic: str | None
    analyzed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    tool: str
    version: str
    mode: str
    target: str
    started_at: str
    completed_at: str
    artifacts: list[InputArtifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "schema_version": "1.0.0",
            "tool": self.tool,
            "version": self.version,
            "mode": self.mode,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "summary": {
                "finding_count": len(self.findings),
                "severity_counts": counts,
                "risk_score": self.risk_score(),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }

    def risk_score(self) -> int:
        score = 0
        for finding in self.findings:
            score += {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}.get(finding.severity, 0)
        return min(score, 100)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
