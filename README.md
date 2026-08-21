# GHOST-FirmwareAnalyzer

Red team assessment and artifact analysis utility. Developed by Abdulaziz (Ghost-SY1).

## Overview

`GHOST-FirmwareAnalyzer` is an technical security utility built under the Ghost-SY1 v4.0-PRO standard. It specializes in `Binary firmware and embedded filesystem inspector`, parsing local artifacts, calculating SHA-256 integrity hashes, evaluating security rule sets, and generating structured JSON, CSV, SARIF 2.1.0, and PDF reports without live exploitation or network execution.

## Key Features & Benefits

- **Strict Input-bound analysis**: Operates exclusively on real local operator-provided inputs.
- **Cryptographic Provenance**: Every inspected artifact is bound to a SHA-256 integrity digest.
- **Multi-Format Reporting**: Native export to JSON, CSV, SARIF 2.1.0, and ReportLab PDF.
- **Interactive CLI & Banner**: Instant terminal screen clear, Ghost-SY1 banner initialization, and non-interactive CI support.

## Use Cases

- Authorized red team security audits and configuration reviews.
- Evidence collection, provenance tracking, and reporting for executive leadership.
- Integration into CI/CD security validation pipelines.

## Installation & Setup

```bash
git clone https://github.com/GhostSy1/GHOST-FirmwareAnalyzer.git
cd GHOST-FirmwareAnalyzer
python3 -m pip install -r requirements.txt
python3 main.py --help
```

## CLI Help & Usage

```bash
python3 main.py --input ./target/ --output report.json --csv report.csv --sarif report.sarif --pdf report.pdf
```

### Command-Line Arguments

- `--input PATH`: Path to target file or directory for assessment.
- `--output PATH`: Path to output JSON report (default: `report.json`).
- `--csv PATH`: Path to output CSV summary table.
- `--sarif PATH`: Path to output SARIF 2.1.0 report for IDE/CI integration.
- `--pdf PATH`: Path to output PDF report.
- `--no-clear`: Skip terminal screen clearing banner initialization.

## Architecture & Integration

`GHOST-FirmwareAnalyzer` integrates cleanly with local evidence ledgers, CI/CD runners, and assessment orchestration platforms (such as `GHOST-AssessmentHub`). It does not execute live network requests or remote commands.


## Disclaimer & Authorized Use

This tool is developed strictly for authorized security assessments, red teaming engagements, and educational demonstrations under explicit written permission. The author and maintainers assume no liability for unauthorized or illegal use.

## Interactive use

```bash
python3 main.py
```

Start with `python3 main.py`. The program asks for the input path and each enabled report path.
Press Enter when an optional report path is offered to skip it.

The command accepts the same values through flags for CI or scripted use. Run `python3 main.py --help` to see the exact options for this repository.

## Output

Reports contain observations from the supplied input, source paths, timestamps, and integrity metadata where supported. An empty result means no rule matched the supplied input; it is not evidence that an entire environment is secure.

## Authorized use

Use the repository only with written permission and within the approved assessment scope. Do not submit credentials, private keys, or unrelated personal data as input.
