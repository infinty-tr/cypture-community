#!/usr/bin/env bash
set -euo pipefail

SURF="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "$SURF" ]]; then
  AT="$ROOT/.cypture/plugin/ACTIVE_TARGET"
  [[ -f "$AT" ]] && SURF="$(head -1 "$AT" | tr -d '[:space:]')"
fi
[[ -z "$SURF" ]] && SURF=$(ls -t targets/*/surface.json 2>/dev/null | head -1 || true)
if [[ -z "$SURF" || ! -f "$SURF" ]]; then
  echo "DECISION: STOP reason=NO_SURFACE"; exit 3
fi
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
DIR="$(dirname "$SURF")"
SIGNALS="$DIR/signals.jsonl"

emit() { # emit <decision-line>  → run.stop_reason yaz (STOP ise), satırı bas
  local line="$1"
  if [[ "$line" == DECISION:\ STOP* ]]; then
    local reason="${line#*reason=}"; reason="${reason%% *}"
    jq --arg r "$reason" '.run.stop_reason=$r' "$SURF" > "$SURF.tmp" 2>/dev/null && mv "$SURF.tmp" "$SURF" || true
    bash "$ROOT/scripts/kb_save.sh" "$SURF" >/dev/null 2>&1 || true
  else
    jq '.run.stop_reason=""' "$SURF" > "$SURF.tmp" 2>/dev/null && mv "$SURF.tmp" "$SURF" || true
  fi
  echo "$line"
}

WD="$(bash "$ROOT/scripts/agent_health.sh" "$SURF" 2>/dev/null || true)"
WD_LINES="$(printf '%s\n' "$WD" | grep -E '^CANCEL:|^RESPAWN:|^UYARI:' || true)"
[[ -n "$WD_LINES" ]] && printf '%s\n' "$WD_LINES"   # orkestratör: background_cancel + model_pick ile respawn

set +e; bash "$ROOT/scripts/model_pick.sh" "$SURF" any >/dev/null 2>&1; MP=$?; set -e
if [[ "$MP" -eq 1 ]]; then
  emit "DECISION: STOP reason=NO_WORKING_MODEL   (tüm modeller kalıcı bitti: kota/ödeme/down — operatör model/sağlayıcı düzeltsin)"; exit 0
elif [[ "$MP" -eq 2 ]]; then
  emit "DECISION: CONTINUE-WAIT reason=models_cooling   (tüm modeller GEÇİCİ rate/down — durma; kısa bekle, sonra model_pick ile devam)"; exit 0
fi

read -r UNREACH BSPENT BMAX VALIDATED <<<"$(jq -r '
  [ (.run.unreachable // false), (.run.budget_spent // 0), (.run.budget_max // 100000),
    ([.findings[]? | select(.state=="validated" or .state=="reported")] | length) ] | @tsv' "$SURF")"

LANDED=0
if [[ -s ${CYP_FEED_DIR:-/cyp}/findings.ndjson ]]; then
  LANDED=$(grep -c '"title"' ${CYP_FEED_DIR:-/cyp}/findings.ndjson 2>/dev/null || echo 0)
fi
if [[ "${LANDED:-0}" -eq 0 && -s ${CYP_FEED_DIR:-/cyp}/findings.json ]]; then
  LANDED=$(jq 'length' ${CYP_FEED_DIR:-/cyp}/findings.json 2>/dev/null || echo 0)
fi
if [[ "${LANDED:-0}" -eq 0 && -f ${CYP_FEED_DIR:-/cyp}/feed.jsonl ]]; then
  LANDED=$(grep -c '"t":"find"' ${CYP_FEED_DIR:-/cyp}/feed.jsonl 2>/dev/null || echo 0)
fi
[[ "$LANDED" =~ ^[0-9]+$ ]] || LANDED=0
if [[ "$LANDED" -gt "${VALIDATED:-0}" ]]; then VALIDATED="$LANDED"; fi

if [[ "$UNREACH" == "true" ]]; then emit "DECISION: STOP reason=UNREACHABLE"; exit 0; fi
if [[ "$BSPENT" -ge "$BMAX" ]]; then emit "DECISION: STOP reason=BUDGET_EXHAUSTED   (spent=$BSPENT/$BMAX)"; exit 0; fi

BEST="$(bash "$ROOT/scripts/score_hypotheses.sh" "$SURF" 2>/dev/null | head -1)"
if [[ -n "$BEST" ]]; then
  IFS=$'\t' read -r SC TYPE HOST CLS PARAM HINT <<<"$BEST"
  case "$TYPE" in
    chain_opp)          emit "DECISION: CONTINUE-DEEPEN host=$HOST reason=chain | $HINT";;
    belief_test)        emit "DECISION: CONTINUE-DEEPEN reason=falsify_belief | $HINT";;
    pending_signal)     emit "DECISION: CONTINUE-DEEPEN reason=validate_signals($HOST:$CLS) | $HINT";;
    oob_hit)            emit "DECISION: CONTINUE-DEEPEN host=$HOST reason=oob_poll | $HINT";;
    open_hypothesis)    emit "DECISION: CONTINUE-NEW-HYPOTHESIS host=$HOST class=$CLS param=$PARAM reason=$HINT";;
    host_class_pending) emit "DECISION: CONTINUE-DEEPEN host=$HOST class=$CLS reason=class_cell_pending";;
    host_deepen)        emit "DECISION: CONTINUE-DEEPEN host=$HOST reason=raise_depth_L3";;
    host_untested)
      NEXT="$(bash "$ROOT/scripts/score_hypotheses.sh" "$SURF" 2>/dev/null | awk -F'\t' '$2=="host_untested"{print $3}' | head -8 | tr '\n' ',' | sed 's/,$//')"
      emit "DECISION: CONTINUE-NEW-HOST next=${NEXT:-$HOST} reason=host_untested";;
    *)                  emit "DECISION: CONTINUE-DEEPEN host=$HOST reason=$TYPE";;
  esac
  exit 0
fi

set +e; bash "$ROOT/scripts/theory_gate.sh" "$SURF" >/dev/null 2>&1; TG=$?; set -e
if [[ "$TG" -eq 10 ]]; then
  emit "DECISION: CONTINUE-NEW-HYPOTHESIS reason=theory_open_questions (reason_hypotheses.sh calistir + acik teori sorularini dikkatlice incele/cevapla — checklist degil, mantik)"; exit 0; fi
DEEP_FLOOR="${CYP_DEEPEN_BUDGET_FLOOR_PCT:-0}"
if [[ "$BMAX" -gt 0 && "$DEEP_FLOOR" -gt 0 ]]; then
  PCT=$(( BSPENT * 100 / BMAX ))
  if [[ "$PCT" -lt "$DEEP_FLOOR" ]]; then
    emit "DECISION: CONTINUE-NEW-HYPOTHESIS reason=budget_floor_deepen(spent=%$PCT<%$DEEP_FLOOR) | denenmemiş param×sınıf + iç/gizli endpoint ara, kolay bulguları gerçek-etkiye yükselt."
    exit 0
  fi
fi

if [[ "$VALIDATED" -gt 0 ]]; then
  emit "DECISION: STOP reason=VULN_FOUND_AND_EXHAUSTED   (validated=$VALIDATED)"; exit 0; fi
emit "DECISION: STOP reason=EXHAUSTED_NO_VULN   (anlasildi+derinlik+mantik+butce tukendi, 0_validated)"; exit 0
