from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .models import AnalysisReport


def write_json(report: AnalysisReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(report: AnalysisReport, path: Path) -> None:
    fields = ["rule_id", "title", "severity", "confidence", "description", "evidence", "source", "location", "remediation", "tags"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in report.findings:
            row = finding.to_dict()
            row["tags"] = ",".join(row["tags"])
            writer.writerow({field: row.get(field) for field in fields})


def write_sarif(report: AnalysisReport, path: Path) -> None:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in report.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title, "shortDescription": {"text": finding.title}, "help": {"text": finding.remediation or finding.description}})
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": f"{finding.description} Evidence: {finding.evidence}"},
            "properties": {"severity": finding.severity, "confidence": finding.confidence, "source": finding.source, "tags": list(finding.tags)},
        }
        if finding.location:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.location}}}]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": report.tool, "version": report.version, "rules": list(rules.values())}}, "results": results, "properties": {"target": report.target, "mode": report.mode, "risk_score": report.risk_score()}}],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
