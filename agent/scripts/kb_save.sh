#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: kb_save.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NORM="$(mktemp)"; jq -s '.[0] // {}' "$SURF" > "$NORM" 2>/dev/null || echo '{}' > "$NORM"
TARGET="$(jq -r '.target // ""' "$NORM")"
[[ -z "$TARGET" ]] && { echo "KB: surface.target boş, kaydedilemedi." >&2; rm -f "$NORM"; exit 0; }
mkdir -p "$ROOT/targets/_knowledge"
KB="$ROOT/targets/_knowledge/${TARGET}.json"
TODAY="$(date +%F)"
[[ -f "$KB" ]] || echo '{}' > "$KB"

jq --slurpfile old "$KB" --arg today "$TODAY" '
  ($old[0] // {}) as $o
  | {
    target: .target,
    last_run: $today,
    purpose: ((.theory.purpose // "") | if .=="" then ($o.purpose // "") else . end),
    confirmed_tech: (( ([.assets[]?.tech // []] | flatten) + ($o.confirmed_tech // []) ) | map(select(.!="")) | unique),
    auth_model: ((.run.kb_auth_model // "") | if .=="" then ($o.auth_model // "") else . end),
    tested_surface: ( [ .assets[]? | select((.depth_achieved // "L0") != "L0")
        | {host:.host, depth:.depth_achieved,
           classes:((.test_classes // {}) | to_entries | map(select(.value==true)|.key))} ] ),
    dead_ends: ( ((.kb_dead_ends // []) + [ .hypotheses[]? | select(.state=="tested") | (.host+" "+(.class//"")+" "+(.param//"")) ]) | unique ),
    suspicious: ( [ .hypotheses[]? | select(.state=="open") | {host:.host, class:.class, param:(.param//""), note:(.angle//"")} ]
                  + [ .oob_canaries[]? | select((.confirmed//false)|not) | {host:.host, class:.class, param:(.param//""), note:("oob doğrulanmadı: "+.fqdn)} ] ),
    known_findings: ( ([ .findings[]? | select(.state=="validated" or .state=="reported")
        | {class:.type, host:.host, endpoint:(.endpoint//""), status:.state} ] + ($o.known_findings // [])) | unique )
  }
' "$NORM" > "$KB.tmp" && mv "$KB.tmp" "$KB"
rm -f "$NORM"

echo "KB KAYDEDİLDİ [$TARGET] → $KB (last_run=$TODAY)"
jq -r '"  tech="+((.confirmed_tech//[])|join(","))+"  tested_host="+((.tested_surface//[])|length|tostring)+"  suspicious="+((.suspicious//[])|length|tostring)+"  known_findings="+((.known_findings//[])|length|tostring)' "$KB"
if [[ -z "${KB_NOMINE:-}" ]]; then bash "$ROOT/scripts/kb_mine.sh" 2>/dev/null | tail -1 || true; fi
