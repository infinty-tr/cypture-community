#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-}"; SURF="${2:-}"
[[ -z "$TARGET" || -z "$SURF" ]] && { echo "KULLANIM: kb_load.sh <target> <surface.json>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KB="$ROOT/targets/_knowledge/${TARGET}.json"

if [[ ! -f "$KB" ]]; then
  echo "KB: ${TARGET} için kayıt yok (ilk koşu) — tam recon. (kayıt: $KB)"
  exit 0
fi
jq -e . "$KB" >/dev/null 2>&1 || { echo "KB: $KB bozuk JSON, atlanıyor." >&2; exit 0; }

jq --slurpfile kb "$KB" '
  ($kb[0]) as $k
  | .run //= {}
  | .run.kb_loaded = true
  | .run.kb_auth_model = ($k.auth_model // "")
  | .run.kb_confirmed_tech = ($k.confirmed_tech // [])
  | .kb_dead_ends = ($k.dead_ends // [])
  | .hypotheses = (.hypotheses // [])
  | reduce (($k.suspicious // [])[]) as $s (.;
      .hypotheses += [{id:("h-kb-susp-"+($s|@base64|.[0:8])), host:($s.host // ($s|tostring)),
        param:($s.param // ""), class:($s.class // "recheck"),
        angle:("KB-ŞÜPHELİ (önceki koşu yarım): "+($s.note // ($s|tostring))),
        state:"open", priority_boost:true}])
  | .findings = (.findings // [])
  | reduce (($k.known_findings // [])[]) as $f (.;
      if any(.findings[]?; .host==($f.host // "") and .type==($f.class // $f.type // "")) then .
      else .findings += [{type:($f.class // $f.type // "info"), host:($f.host // ""),
        endpoint:($f.endpoint // ""), state:"reported", boundary:"confidentiality",
        impact:("KB: önceki koşuda "+($f.status // "bulundu")), severity:"INFO",
        baseline_req:"kb", deviation_req:"kb", signal_ref:"kb"}] end)
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

DE=$(jq -r '(.kb_dead_ends // [])|length' "$SURF"); SU=$(jq -r '[.hypotheses[]?|select(.id|startswith("h-kb-susp"))]|length' "$SURF")
echo "KB YÜKLENDİ [$TARGET]: tech=$(jq -r '(.run.kb_confirmed_tech//[])|join(",")' "$SURF") · auth='$(jq -r '.run.kb_auth_model' "$SURF")' · dead_ends=$DE · şüpheli→hipotez=$SU"
echo "  (re-run: bilinen yüzeyi atla, ŞÜPHELİ'yi öncele, DERİN git. last_run önceki: $(jq -r '.last_run // "?"' "$KB"))"
