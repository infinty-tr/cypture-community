#!/usr/bin/env bash
# Cypture CE all-in-one entrypoint: wire opencode auth from the operator's provider
# key, then start the web server (which drives the in-container live runner).
set -uo pipefail

DATA_DIR=/root/.local/share
mkdir -p "$DATA_DIR/opencode" "$DATA_DIR/cypture-agent" /data /work

# ── opencode auth ────────────────────────────────────────────────────────────
# Priority: a mounted opencode auth.json (multi-provider, from `opencode auth login`)
# wins; otherwise generate one from CYPTURE_LLM_API_KEY for the model's provider.
KEY="${CYPTURE_LLM_API_KEY:-${CYP_LLM_API_KEY:-}}"
MODEL="${CYPTURE_RUNNER_MODEL:-openai/gpt-4o-mini}"
PROV="${CYPTURE_LLM_PROVIDER:-}"
if [ -z "$PROV" ]; then
  case "$MODEL" in */*) PROV="${MODEL%%/*}" ;; *) PROV="openai" ;; esac
fi

if [ -s "$DATA_DIR/opencode/auth.json" ]; then
  echo "cypture: using existing/mounted opencode auth.json"
elif [ -n "$KEY" ]; then
  AUTH="$(jq -nc --arg p "$PROV" --arg k "$KEY" '{($p):{type:"api",key:$k}}')"
  printf '%s' "$AUTH" > "$DATA_DIR/opencode/auth.json"
  printf '%s' "$AUTH" > "$DATA_DIR/cypture-agent/auth.json"
  chmod 600 "$DATA_DIR/opencode/auth.json" "$DATA_DIR/cypture-agent/auth.json" 2>/dev/null || true
  echo "cypture: wrote opencode auth.json for provider '$PROV' (model '$MODEL')"
else
  echo "cypture: WARNING — no CYPTURE_LLM_API_KEY and no mounted auth.json;" >&2
  echo "         live scans will NOT authenticate. Set CYPTURE_LLM_API_KEY in .env" >&2
  echo "         or mount ~/.local/share/opencode/auth.json into the container." >&2
fi

# ── runtime wiring (the per-machine host wiring, baked once here) ─────────────
export PATH="/usr/local/bin:${PATH}"
export CYPTURE_RUNNER="${CYPTURE_RUNNER:-live}"
export CYPTURE_AGENT_BIN="${CYPTURE_AGENT_BIN:-/usr/local/bin/cypture-agent}"
export OPENCODE_BIN="${OPENCODE_BIN:-$(command -v opencode || echo /usr/local/bin/opencode)}"

echo "cypture: engine=$(command -v cypture-engine) agent-bin=$CYPTURE_AGENT_BIN opencode=$OPENCODE_BIN runner=$CYPTURE_RUNNER model=$MODEL"

exec /usr/local/bin/cypture
