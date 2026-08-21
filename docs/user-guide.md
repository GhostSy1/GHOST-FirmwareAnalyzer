# GHOST-FirmwareAnalyzer User Guide

## Purpose

This guide explains how to run `GHOST-FirmwareAnalyzer` from a local terminal and how to interpret its output. The tool reads the input supplied by the operator and does not treat an empty result as proof that a system is secure.

## First run

```bash
python3 main.py
```

When no arguments are supplied, the launcher asks for every required value supported by this repository. Optional report paths can be left empty. The launcher does not invent a target, a finding, a credential, or a network response.

## Help

```bash
python3 main.py --help
```

The help output is the authoritative list of flags for this repository. The interactive prompts and the flags use the same underlying execution path.

## Scripted use

Use the exact flags displayed by `--help` in CI or another script. A typical file-based analyzer accepts an input path and report paths:

```bash
python3 main.py --input ./approved-input --output report.json --csv report.csv --sarif report.sarif
```

`GHOST-AssessmentHub`, `GHOST-ControlValidation`, and `GHOST-EngagementControl` use their own manifest or plan arguments. Run `python3 main.py --help` in those repositories before scripting them.

## Reading results

The JSON report is the source record. CSV is intended for tabular review and SARIF is intended for compatible code-scanning viewers. Where PDF generation is enabled, the PDF is a presentation of the recorded report and not a separate scan. Findings must be reviewed against the supplied evidence and the approved scope.

## Inputs and outputs

The input must be a file or directory that the operator is authorized to inspect. Output paths should point to a writable directory outside the evidence when possible. Keep reports and evidence access-controlled because reports can contain sensitive metadata.

## Limitations

Static analysis cannot prove the absence of a vulnerability. Network, cloud, identity, or mobile conclusions require the corresponding exported evidence or an explicitly authorized test path supported by the tool. The tool does not replace manual review.

## Responsible use

Use the repository for authorized assessments, education, and controlled research. Stop the assessment if scope, authorization, or data-handling conditions change.
