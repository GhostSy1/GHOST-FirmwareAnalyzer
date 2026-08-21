# GHOST-FirmwareAnalyzer CLI Reference

## Basic Execution
```bash
python3 main.py --input ./target-dir/ --output report.json --csv report.csv --sarif report.sarif --pdf report.pdf
```

## Arguments
- `--input`: Path to target file or directory for assessment.
- `--output`: Path to output JSON report (default: `report.json`).
- `--csv`: Path to output CSV summary table.
- `--sarif`: Path to output SARIF 2.1.0 report for IDE/CI integration.
- `--pdf`: Path to output professional PDF executive report.
- `--no-clear`: Skip terminal screen clearing banner initialization.
