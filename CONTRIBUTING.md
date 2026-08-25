# Contributing to Cypture

Thanks for your interest in improving Cypture. This project is offensive security
tooling — please keep contributions focused on **authorized / defensive** use.

## Getting started

1. Fork and clone the repository.
2. Install Go 1.26+.
3. `cp .env.example .env` and set at least `CYPTURE_SESSION_SECRET` and
   `ADMIN_PASSWORD`.
4. `make run` (uses the `sim` runner by default — no external calls).

## Before you open a pull request

- `make vet` — must be clean.
- `go test ./...` — must pass.
- `gofmt -w` your changed Go files.
- Keep changes focused; describe what and why in the PR.
- Do not commit secrets, real target data, or large binaries. `.gitignore` already
  excludes `.env`, `data/`, build output, and backups — keep it that way.

## Scope of contributions we welcome

- Bug fixes, tests, and documentation.
- New scanning tools/skills, provider integrations, and report improvements.
- Usability and self‑hosting/deployment improvements.

## Not accepted

- Changes intended to help attack systems without authorization, evade detection for
  malicious purposes, or target a specific third party.

## Reporting security issues

Please do not open a public issue for security vulnerabilities in Cypture itself —
see [`SECURITY.md`](SECURITY.md).

By contributing, you agree that your contributions are licensed under the project's
AGPL‑3.0 license.
