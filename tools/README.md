# Domain Extension

This directory contains a standalone, standard-library-only analyzer for the repository's domain. The extension accepts a file or directory supplied by the operator, records SHA-256 metadata, extracts bounded text evidence, and writes JSON. CSV and SARIF are optional.

The extension is read-only with respect to the input. It does not execute files, open sockets, contact an API, bypass a control, collect credentials, or generate payloads. Findings are observable indicators and require analyst validation.
