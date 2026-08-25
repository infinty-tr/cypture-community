#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: score_hypotheses.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
DIR="$(dirname "$SURF")"; SIG="$DIR/signals.jsonl"
NOW=$(date +%s); TTL="${AGENT_TTL:-600}"

RAW=0; [[ -f "$SIG" ]] && RAW=$(grep -c . "$SIG" 2>/dev/null || true); RAW="${RAW:-0}"
AUD=0; [[ -f "$DIR/signals.audited" ]] && AUD=$(tr -dc '0-9' < "$DIR/signals.audited" 2>/dev/null); AUD="${AUD:-0}"
UNAUD=$(( RAW - AUD )); [[ "$UNAUD" -lt 0 ]] && UNAUD=0

jq -r --argjson now "$NOW" --argjson ttl "$TTL" --argjson unaud "$UNAUD" '
  def cw(c):  # sınıf ağırlığı (impact)
    (c|ascii_downcase) as $c
    | if   ($c|test("rce|sqli|ssrf|idor|bola|authz_idor|auth_bypass|account_takeover")) then 5
      elif ($c|test("authz|bfla|tenant|privilege")) then 5
      elif ($c|test("xss|ssti|lfi|path_traversal|deser|xxe|nosqli|command|jwt|oauth|business_logic|gap|anomaly")) then 4
      elif ($c|test("csrf|open_redirect|mass_assignment|file_upload|session|graphql|prototype")) then 3
      else 1 end;
  def fresh_lease: ((.assigned_to // "") != "") and (($now - (.assigned_at // 0)) <= $ttl);
  def done_classes: ((.test_classes // {}) | to_entries | map(select(.value==true)|.key));
  def dnum(d): ({"L0":0,"L1":1,"L2":2,"L3":3,"L4":4}[d] // 0);
  def ctxmult: ((.angle//"")+(.intent//"")+(.param//"")+(.host//"")+(.class//"")) as $x
    | if   ($x|test("transfer|balance|payment|payout|wallet|/pay|fund|invoice|transaction|/admin|token|secret|tenant|privilege|bfla";"i")) then 1.6
      elif ($x|test("avatar|comment|theme|locale|favicon|/static|preference|wishlist";"i")) then 0.5
      else 1.0 end;

  [
    ( .hypotheses[]? | select(.state=="open" and (.class=="chain"))
      | {score: 6.0, type:"chain_opp", host:.host, class:"chain", param:(.param//""), hint:(.angle // "zincir")} ),

    ( .findings[]? | select(.state=="candidate")
      | {score: (4.7 + (cw(.type)/100)), type:"pending_signal", host:.host, class:(.type), param:"", hint:"candidate doğrula/çürüt"} ),
    ( if $unaud > 0 then {score:4.6, type:"pending_signal", host:"-", class:"raw", param:"", hint:"audit_signals çalıştır (\($unaud) denetlenmemiş)"} else empty end ),

    ( .beliefs[]? | select((.status//"open")=="open" and (.confidence//0) >= 0.35)
      | {score: ([4.3, (4.0 * (.confidence//0.5))] | min), type:"belief_test", host:"-", class:"belief", param:"",
         hint:("INANC curut/kanitla [conf "+((.confidence//0)|tostring)+"]: "+.claim)} ),

    ( .oob_canaries[]? | select((.injected // false) and ((.confirmed // false)|not) and ((.poll_count // 0) < 3))
      | {score:4.5, type:"oob_hit", host:.host, class:(.class), param:(.param//""), hint:"oob_poll: canary \(.token)"} ),

    ( .hypotheses[]? | select(.state=="open" and (.class!="chain"))
      | {score: (if (.impact != null) then ([4.4, ((.impact) * 0.85)] | min)
                  else ((cw(.class)) * (if (.priority_boost//false) then 0.85 else 0.5 end) / 2 * ctxmult) end),
         type:"open_hypothesis", host:.host, class:.class, param:(.param//""), hint:(.angle // "test et")} ),

    ( .assets[]? | select((fresh_lease|not) and (dnum(.depth_achieved//"L0") >= 1) and (dnum(.depth_achieved//"L0") < 3))
      | {score: (2 * (if .priority=="high" then 0.7 else 0.45 end) / 3),
         type:"host_deepen", host:.host, class:"depth", param:"", hint:"L3+ dikkatlice incele (lens: applicable_classes)"} ),

    ( .assets[]? | select((fresh_lease|not) and ((.depth_achieved//"L0")|test("^(L0)?$")))
      | {score: ((if .priority=="high" then 3 elif .priority=="medium" then 1.5 else 1 end) * 0.3 / 3),
         type:"host_untested", host:.host, class:"-", param:"", hint:"yeni host spawn"} )
  ]
  | sort_by(-.score)
  | .[] | [(.score*1000|floor/1000), .type, .host, .class, .param, .hint] | @tsv
' "$SURF"
