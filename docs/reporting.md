# Reporting and Evidence

## Canonical JSON

The JSON report is the source representation for the other outputs. It contains a schema version, tool version, mode, target, timestamps, artifact metadata, severity counts, a transparent triage score, findings, and safety metadata.

```json
{
  "schema_version": "1.0.0",
  "tool": "GHOST-FirmwareAnalyzer",
  "version": "3.0.0",
  "mode": "static-file",
  "summary": {
    "finding_count": 1,
    "severity_counts": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 1,
      "critical": 0
    },
    "risk_score": 30
  }
}
```

The excerpt in `evidence` is bounded to 500 characters. This reduces accidental disclosure but is not a substitute for reviewing the report before distribution.

## CSV

CSV flattens each finding into one row. It is useful for triage queues and spreadsheet review, but it does not preserve every report-level metadata field. Use JSON when provenance and artifact inventory are required.

## SARIF

SARIF output uses version 2.1.0 and includes a rule catalog, result level, evidence message, severity, confidence, source, and tags. The tool emits a SARIF document but does not upload it anywhere. Upload decisions and repository permissions remain with the operator.

## Hash-chained ledger

Each ledger line has this shape:

```json
{
  "finding_count": 2,
  "previous_hash": "...",
  "record_hash": "...",
  "report_sha256": "...",
  "target": "/review/image.bin"
}
```

`record_hash` is calculated from the other fields in canonical key order. The next record stores the previous `record_hash`. This provides tamper-evident sequencing for the local file. It is not an immutable remote ledger and does not prevent an administrator with write access from deleting the entire file.

For stronger custody, store a copy of the ledger and report in a write-restricted evidence system, sign release packages through the organization's approved key-management process, and retain acquisition metadata outside this repository.

## Recommended review workflow

First, hash the source through the analyzer and compare the digest with the independent acquisition record. Second, review format and artifact inventory. Third, triage findings by severity and confidence. Fourth, validate each observation against the device documentation and build provenance. Finally, record the disposition and preserve the report, ledger, and supporting evidence under the case identifier.
