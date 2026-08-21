# GHOST-FirmwareAnalyzer

Professional security assessment and artifact analysis utility. Developed by Abdulaziz (Ghost-SY1).

## Overview

`GHOST-FirmwareAnalyzer` is an advanced, production-grade security utility built under the Ghost-SY1 v4.0-PRO standard. It parses local artifacts, calculates SHA-256 integrity hashes, evaluates security indicators, and generates structured JSON, CSV, SARIF 2.1.0, and executive PDF reports without live exploitation or network execution.

## Features

- **Strict Zero-Simulation Engine**: Operates exclusively on real local operator-provided inputs.
- **Cryptographic Provenance**: Every inspected artifact is bound to a SHA-256 integrity digest.
- **Multi-Format Reporting**: Native export to JSON, CSV, SARIF 2.1.0, and ReportLab PDF.
- **Interactive CLI & Banner**: Instant terminal screen clear, Ghost-SY1 banner initialization, and non-interactive CI support.

## Installation & Setup

```bash
git clone https://github.com/GhostSy1/GHOST-FirmwareAnalyzer.git
cd GHOST-FirmwareAnalyzer
python3 main.py --help
```

## Usage Example

```bash
python3 main.py --input ./target/ --output report.json --sarif report.sarif --pdf report.pdf
```

## Documentation

- Architecture: `docs/architecture.md`
- CLI Reference: `docs/cli-reference.md`
- Security Policy: `SECURITY.md`
- Contributing: `CONTRIBUTING.md`
