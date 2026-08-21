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
- `--pdf`: Path to output PDF report.
- `--no-clear`: Skip terminal screen clearing banner initialization.

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
