# GHOST-FirmwareAnalyzer CLI and Operations Reference

## Entry point

The repository currently documents or contains the following starting point:

```bash
python3 main.py --help
```

Do not infer a command from the project name. Read the repository README and use only the documented target and authorization boundary. If the program needs a file, directory, address, account, or API credential, the operator must provide an explicitly authorized value.

## Output contract

A useful operational tool should document its output format, exit codes, error behavior, logging policy, and whether it makes network requests. Reports should distinguish observed data, inferred context, and analyst conclusions. Secrets must be redacted from terminal output and reports.

## Safe operating procedure

Work from a read-only copy of evidence where possible. Capture the tool version, input digest, UTC time, and authorization reference. Review the result before sharing it. Stop if an operation would require bypassing access controls, collecting credentials, executing untrusted content, or contacting a target outside the approved scope.
