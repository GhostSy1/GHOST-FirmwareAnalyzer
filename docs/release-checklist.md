# GHOST-FirmwareAnalyzer Release Checklist

| Gate | Required before a public release |
|---|---|
| Scope | README describes the actual purpose, input boundary, and authorized-use requirement |
| Correctness | Source compiles or builds and the documented test command passes |
| Evidence | Findings are derived from supplied input and include source context |
| Safety | No credentials, private keys, customer data, or destructive defaults are tracked |
| Documentation | Architecture, CLI, outputs, limitations, and recovery guidance are present |
| CI | A reproducible quality workflow runs on pull requests and pushes |
| Change record | User-visible changes are recorded in `CHANGELOG.md` |

This checklist is a release gate, not a claim that every item is already complete. Mark an item complete only after the corresponding evidence exists in the repository.
