# Security Policy

## Scope

This policy covers the source code and documentation in this repository. Use the project only for systems, files, and accounts for which you have explicit authorization.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability, credential, private key, or customer data. Contact the repository owner through the private security contact configured on GitHub and include a reproducible description, affected revision, impact, and a safe validation path. Remove secrets from the report and use redacted evidence.

## Release hygiene

Pull requests must not contain access tokens, private keys, production data, unapproved exploit material, or claims that are not supported by the implementation. Security-sensitive changes require tests and a review of the generated artifacts before release.
