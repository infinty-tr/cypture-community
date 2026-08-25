# Cypture — Community Edition

Cypture is a self-hostable platform for running **authorized** web‑application
security assessments. A Go web application (authentication, engagements, scan
lifecycle, live streaming, findings, and reports) drives a containerized scanning
engine that orchestrates an LLM‑based agent to probe a target and report findings.

This repository is the **Community Edition** — a reduced, single‑operator build meant
for people who want to run their own instance, study the code, or build on top of it.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit, written
> permission to test. You are responsible for how you use this software.

---

## How it works

Cypture has three cooperating pieces:

1. **Web backend (`cmd/cypture`, `internal/…`)** — a Go HTTP server with SQLite
   storage. It handles the admin login, scan lifecycle, live WebSocket streaming,
   findings storage/moderation, and Markdown/HTML report generation.
2. **Scanning engine (`cmd/cypture-engine`, `internal/engine`)** — Cypture's own
   MITM HTTP proxy plus an MCP tool server that exposes HTTP‑testing tools
   (`cyp_send_request`, `cyp_create_finding`, …) to the agent. It ships in the
   scan container image.
3. **Agent runtime** — the process that actually runs the LLM agent, reading the
   agent prompts in `agent/.cypture/agents/` and the playbooks in `agent/skills/`,
   and calling the engine's MCP tools. It is invoked as `cypture-agent`
   (configurable via `CYPTURE_AGENT_BIN`).

Per scan, the backend launches an isolated container (Docker or a Kubernetes pod)
built from the engine image, passes the target/scope/model as `CYP_*` env vars,
tails the container's live output over a `/cyp` bridge directory, and streams it to
the browser.

> **Note on the agent runtime.** The agent runtime is an LLM‑agent executor that
> reads `agent/.cypture/` config by convention. The community edition ships the
> platform and the engine, but you must supply a compatible agent‑runtime binary
> and point `CYPTURE_AGENT_BIN` at it. Without it, only the `sim` runner (a scripted
> demo that makes no external calls) will run.

---

## Community Edition scope

**Included:** the full web application (admin auth, scan lifecycle, live streaming,
findings, reports), the scanning engine source, the agent prompt/skill set, and the
Docker/Kubernetes runners. Bring your own LLM provider key and model.

**Different from the hosted edition:**

- **Single operator (admin‑only).** There is no self‑registration and no
  customer/multi‑tenant accounts. One admin account, seeded from `ADMIN_EMAIL` /
  `ADMIN_PASSWORD`, logs in and runs scans.
- **No billing.** No payments, subscriptions, quotas, or credit ledger — scans are
  unlimited.
- **Cross‑target learning disabled.** The hosted edition accumulates generalized,
  cross‑engagement "priors" to sharpen future scans; that subsystem is off here.
  Per‑target scan memory (a scan remembering the same target's own prior findings)
  still works.
- **No built‑in exploitation‑hint database**, and a reduced set of specialist agents.

---

## Requirements

- **Go 1.26+** (to build the backend and engine).
- For real scans: **Docker** or a **Kubernetes (k3s)** cluster, an **LLM provider API
  key**, and a **compatible agent‑runtime binary** (see the note above).
- `openssl`, `jq`, `sqlite3`, `curl` for the setup script.

---

## Quick start (development)

```bash
cp .env.example .env
# Edit .env:
#   CYPTURE_SESSION_SECRET  — generate with: openssl rand -hex 32
#   ADMIN_EMAIL / ADMIN_PASSWORD — your seed admin account

make run          # or: go run ./cmd/cypture
```

Open http://127.0.0.1:7777 and log in with the seeded admin account.

The default `CYPTURE_RUNNER=sim` runs a scripted simulation with no external calls —
safe for exploring the UI. To run **real** scans:

```bash
export CYPTURE_LLM_API_KEY=sk-...          # your provider key
export CYPTURE_RUNNER_MODEL=openai/gpt-4o-mini
make docker-image                          # build cypture-engine:latest
export CYPTURE_RUNNER=docker                # or k8s
# ensure a compatible agent runtime is installed and CYPTURE_AGENT_BIN points to it
go run ./cmd/cypture
```

See `.env.example` for every option.

---

## Build & test

```bash
make build        # build the server binary into bin/cypture
make vet          # go vet ./...
go test ./...     # run the test suite
make docker-image # build the scan engine image
```

---

## Configuration

All configuration is via environment variables — see `.env.example` for the full,
documented list. Highlights:

| Variable | Purpose |
| --- | --- |
| `CYPTURE_SESSION_SECRET` | 32+ byte secret for signed cookies / CSRF (**required in prod**) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Seed admin account, created on first boot |
| `CYPTURE_RUNNER` | `sim` / `docker` / `k8s` |
| `CYPTURE_LLM_API_KEY` / `CYPTURE_RUNNER_MODEL` | Your LLM provider key and model id |
| `CYPTURE_AGENT_BIN` | Path/name of the agent‑runtime binary (default `cypture-agent`) |
| `CYPTURE_ENGINE_BIN` | Name of the engine binary in the image (default `cypture-engine`) |
| `CYPTURE_DB_PATH` | SQLite database path |
| `CYPTURE_REPORT_COMPANY` / `_SITE` / `_PARTNER` / `_CLASSIFICATION` / `_LOGO_DATA_URI` | Branding printed on generated reports (default: generic "Cypture") |

---

## Repository layout

```
cmd/          Go entrypoints (server, engine, TUI)
internal/     Go backend (auth, config, db, engine, kb, models, orchestrator, server, …)
frontend/     Static admin web UI (HTML/CSS/JS)
agent/        Agent prompts, skills, and orchestration scripts used by the runtime
docker/       Engine container image
deploy/       Deployment configs (Caddy, k8s NetworkPolicy)
```

---

## Security

This is offensive security tooling. Use it only against systems you are authorized to
test. Run behind authentication, keep your `.env` secret, and prefer the network
isolation the Docker/Kubernetes runners provide (the k8s runner ships an egress
NetworkPolicy that blocks cloud‑metadata and private ranges). To report a
vulnerability in Cypture itself, see [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Licensed under the **GNU Affero General Public License v3.0** (AGPL‑3.0). See
[`LICENSE`](LICENSE). In short: you may use, modify, and self‑host this software, but
if you run a modified version as a network service, you must make your modified
source available to its users.
