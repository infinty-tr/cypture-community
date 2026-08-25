# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability **in Cypture itself**, please report it
privately rather than opening a public issue.

- Open a [GitHub security advisory](../../security/advisories/new) for this
  repository, **or** contact the maintainers privately.
- Include a description, affected version/commit, and reproduction steps or a proof
  of concept.
- Please give us a reasonable window to investigate and ship a fix before any public
  disclosure.

We will acknowledge your report, keep you updated, and credit you (if you wish) once
a fix is released.

## Scope

In scope: authentication/session handling, access control, injection, SSRF in the
scanner's own control plane, container/pod isolation escapes, secret handling, and
similar issues in this codebase.

Out of scope: findings produced *by* Cypture against a target you scanned (those are
the target's issues), and reports about using Cypture against systems you are not
authorized to test.

## Operating Cypture safely

- Keep `.env` and any provider API keys secret; never commit them.
- Run the backend behind authentication and, ideally, a reverse proxy with TLS.
- Prefer the Docker/Kubernetes runners for scan isolation; the Kubernetes runner
  ships an egress NetworkPolicy that blocks cloud‑metadata and private ranges.
- Only scan targets you are authorized to test.
