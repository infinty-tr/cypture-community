#!/usr/bin/env bash
set -euo pipefail

umask 0022

export CYP_FEED_PATH=/cyp/feed.jsonl
export CYP_TRAFFIC_PATH=/cyp/traffic.ndjson
export CYP_LLM_ERR_DUMP=/cyp/llm_error.json
mkdir -p /cyp /cyp/agents /work

/usr/local/bin/cypture agents >/dev/null 2>&1 || true
CORE=/root/.cypture-tui/core
export CYP_KB="$CORE/knowledge/.kb/chunks.ndjson"
if [ -d "$CORE/scripts" ] && [ -d /agent/scripts ]; then
  for s in "$CORE"/scripts/*; do
    b=$(basename "$s"); [ -e "/agent/scripts/$b" ] || ln -sf "$s" "/agent/scripts/$b"
  done
fi

CA_DST=/usr/local/share/ca-certificates/cypture-proxy.crt
CYP_PROXY_ONLY=1 CYP_PROXY_ADDR=127.0.0.1:8080 CYP_CA_EXPORT="$CA_DST" /usr/local/bin/cypture-engine &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 25); do [ -s "$CA_DST" ] && break; sleep 0.2; done
if [ -s "$CA_DST" ]; then
  update-ca-certificates >/dev/null 2>&1 && echo "cypture-engine: MITM CA sistem güven deposuna kuruldu" || true
  export NODE_EXTRA_CA_CERTS="$CA_DST"
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
fi
export CURL_HOME=/root

echo "cypture: izole ortam hazırlanıyor"

if [ -n "${CYP_LLM_API_KEY_FILE:-}" ] && [ -r "${CYP_LLM_API_KEY_FILE}" ]; then
  CYP_LLM_API_KEY="$(cat "${CYP_LLM_API_KEY_FILE}")"
fi
PROV="${CYP_MODEL%%/*}"
[ "$PROV" = "${CYP_MODEL:-}" ] && PROV="${CYP_LLM_PROVIDER:-openai}"
if [ -n "${CYP_LLM_API_KEY:-}" ] && [ -n "$PROV" ]; then
  mkdir -p /root/.local/share/cypture-agent
  jq -nc --arg p "$PROV" --arg k "$CYP_LLM_API_KEY" '{($p):{type:"api",key:$k}}' \
    > /root/.local/share/cypture-agent/auth.json
fi

case "$PROV" in
  openrouter) BASE_URL_P="https://openrouter.ai/api/v1"; AUTH_FIELD="\"apiKeyEnv\":\"OPENROUTER_API_KEY\"" ;;
  openai)     BASE_URL_P="https://api.openai.com/v1";      AUTH_FIELD="\"apiKeyEnv\":\"OPENAI_API_KEY\"" ;;
  anthropic)  BASE_URL_P="https://api.anthropic.com/v1";   AUTH_FIELD="\"apiKeyEnv\":\"ANTHROPIC_API_KEY\"" ;;
  deepseek)   BASE_URL_P="https://api.deepseek.com/v1";    AUTH_FIELD="\"apiKeyEnv\":\"DEEPSEEK_API_KEY\"" ;;
  groq)       BASE_URL_P="https://api.groq.com/openai/v1"; AUTH_FIELD="\"apiKeyEnv\":\"GROQ_API_KEY\"" ;;
  *)          BASE_URL_P="https://api.openai.com/v1";       AUTH_FIELD="\"apiKeyEnv\":\"OPENAI_API_KEY\"" ;;
esac
MODEL_BARE="${CYP_MODEL#*/}"
[ -z "$MODEL_BARE" ] && MODEL_BARE="${CYP_MODEL:-gpt-4o-mini}"
KEY_FIELD="$AUTH_FIELD"
if [ -n "${CYP_LLM_API_KEY:-}" ]; then
  KEY_JSON="$(jq -nc --arg k "$CYP_LLM_API_KEY" '$k')"
  KEY_FIELD="\"apiKey\":${KEY_JSON}"
fi

cat > /work/cypture.json <<JSON
{
  "provider": {
    "baseURL": "${BASE_URL_P}",
    ${KEY_FIELD},
    "models": ["${MODEL_BARE}"],
    "defaultModel": "${MODEL_BARE}",
    "temperature": 0.2
  },
  "maxParallel": ${CYP_MAX_PARALLEL:-12},
  "mcp": {
    "cyp": {
      "type": "local",
      "command": ["/usr/local/bin/cypture-engine"],
      "environment": {
        "CYP_SCOPE_INCLUDES": "${CYP_SCOPE_INCLUDES:-}",
        "CYP_SCOPE_EXCLUDES": "${CYP_SCOPE_EXCLUDES:-}",
        "CYP_PROXY_ADDR": "-",
        "CYP_FEED_PATH": "/cyp/feed.jsonl",
        "CYP_TRAFFIC_PATH": "/cyp/traffic.ndjson"
      },
      "enabled": true
    }
  },
  "cypDir": "/cyp"
}
JSON

cd /work
TARGET="${CYP_TARGET:-}"
SCOPE_ARGS=()

OP_NOTE=""
[ -n "${CYP_OPERATOR_PROMPT:-}" ] && OP_NOTE="${CYP_OPERATOR_PROMPT}"

if [ "${CYP_NUCLEI_AUTO:-0}" = "1" ] && [ -n "$TARGET" ] && command -v nuclei >/dev/null 2>&1; then
  CYP_WEB_FEED=/cyp CYP_TARGET="$TARGET" nohup /usr/local/bin/nuclei_async.sh "$TARGET" >/dev/null 2>&1 &
  echo "cypture: otomatik tarama arka planda başlatıldı (bloklamaz)"
fi

CYP_WEB_FEED=/cyp /usr/local/bin/cypture pentest --project-root /agent --config /work/cypture.json "${SCOPE_ARGS[@]}" -- "$TARGET" || true

if [ ! -s /cyp/findings.json ] && [ -s /cyp/findings.ndjson ]; then
  jq -s '[.[] | select(type=="object")]' /cyp/findings.ndjson > /cyp/findings.json 2>/dev/null || true
fi
