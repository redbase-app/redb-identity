# Contributing to redb.Identity

Thank you for your interest in redb.Identity!

## How to Contribute

Everything below is open to anyone with a GitHub account. You do not need to be a member,
a collaborator, or a previous contributor to open an issue or start a discussion.

### Asking Questions

- [Discussions → Q&A](https://github.com/redbase-app/redb-identity/discussions/categories/q-a) — how to configure a flow, why a token looks the way it does, anything else
- [Discussions → Ideas](https://github.com/redbase-app/redb-identity/discussions/categories/ideas) — propose a direction before it becomes a feature request

### Reporting Issues

- [GitHub Issues](https://github.com/redbase-app/redb-identity/issues) for bug reports and feature requests
- **Security vulnerabilities go to [a private advisory](https://github.com/redbase-app/redb-identity/security/advisories/new), not a public issue.** See [SECURITY.md](SECURITY.md).

### Bug Reports

Please include:
- Package name and version (e.g. `redb.Identity.Core 3.6.0`)
- .NET version and database provider (PostgreSQL / MSSQL / SQLite)
- The flow involved (`authorization_code`, `client_credentials`, `refresh_token`, device code, ...)
- Client type — public or confidential
- The actual request and response, with secrets and tokens redacted
- Expected vs actual behavior, including exception message and stack trace if any

A failing request/response pair is worth more than a description. If the behaviour deviates
from an RFC or the OpenID Connect spec, cite the section — spec compliance is treated as a
correctness requirement here, not a preference.

### Feature Requests

Open an issue or a [Discussion](https://github.com/redbase-app/redb-identity/discussions/categories/ideas) with:
- Description of the feature
- Use case / motivation
- The relevant RFC or OpenID Connect specification, if the feature is a standard one
- Example configuration or API showing the desired shape

## Code Contributions

### Scope

This repository contains the source of the redb.Identity authorization server: the core
engine, the HTTP and gRPC facades, the Management API, the client library, and the web UI.
Pull requests for bug fixes, spec-compliance fixes, documentation improvements, and test
coverage are welcome.

### Getting Started

1. Fork the repository
2. Create a branch: `git checkout -b fix/refresh-token-rotation`
3. Make your changes (see guidelines below)
4. Run the test suite
5. Submit a Pull Request with a clear description

### Code Guidelines

- Follow the existing code style — C# 12, `nullable enable`, `implicit usings`
- Use English for all code identifiers, XML doc summaries, and error messages
- Add `/// <summary>` for all new public classes and methods
- Prefer concrete types and strong typing; do not use `dynamic`
- Error responses must follow the relevant RFC — correct `error` code, correct HTTP status
- Never log tokens, client secrets, authorization codes, or key material
- Do not suppress `CS1591` — every public member must have XML documentation

### Tests

A bug fix needs a test that fails on the unfixed code and passes on the fixed one. Do not
weaken an assertion to make a suite green.

Some suites need external services (PostgreSQL, LDAP, an SMTP sink). If you cannot run
those locally, say so in the pull request rather than skipping them silently.

### Commit Messages

Use the format: `type(scope): description`

Examples:
- `fix(token): reject refresh token reuse after rotation`
- `feat(par): support RFC 9126 pushed authorization requests`
- `docs(deployment): correct the signing key store default`

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
