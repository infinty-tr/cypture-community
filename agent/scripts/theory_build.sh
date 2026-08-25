#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: theory_build.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

PROG="$(mktemp)"
cat > "$PROG" <<'JQ'
def corpus: ([.endpoints[]? | ((.host//"")+(.path//""))] + [.assets[]?.host] | map(ascii_downcase));
def has(re): (corpus | any(.[]; test(re)));
def tech: ([.assets[]?.tech[]?] | map(ascii_downcase) | join(" "));

.theory //= {}
| .theory.purpose = (.theory.purpose // (
    if   has("transfer|payment|wallet|balance|payout|budget|invoice|checkout|billing") then "fintech/odeme veya butce"
    elif has("cart|product|order|shop|store|catalog") then "e-ticaret"
    elif has("tenant|org|workspace|team|account") then "multi-tenant SaaS"
    elif has("post|feed|follow|message|comment|profile") then "sosyal/icerik"
    else "genel web/API uygulamasi" end))
| .theory.value_assets = (if ((.theory.value_assets // [])|length)>0 then (.theory.value_assets) else
    ([ (if has("transfer|payment|wallet|balance|payout|fund|budget|invoice|checkout") then {asset:"para/islem",sensitivity:5} else empty end),
       (if has("token|secret|api[_-]?key|password|credential|/admin") then {asset:"kimlik/admin/sir",sensitivity:5} else empty end),
       (if has("user|profile|account|email|address|phone|kyc|ssn|identity") then {asset:"PII",sensitivity:4} else empty end),
       (if has("upload|file|media|document|export|attachment") then {asset:"dosya/belge",sensitivity:3} else empty end),
       (if has("transaction|history|record|report|statement") then {asset:"islem/kayit-gecmisi",sensitivity:4} else empty end) ]) end)
| .theory.actors = (if ((.theory.actors // [])|length)>0 then (.theory.actors) else
    ([ {role:"user",caps:["kendi-verisi","kendi-islemleri"]},
       (if has("/admin|/manage|/console|/backoffice") then {role:"admin",caps:["tumunu-gor-yonet"]} else empty end),
       (if has("tenant|org|workspace|team") then {role:"tenant-uye",caps:["tenant-verisi"]} else empty end),
       (if has("household|member|share|invite|collaborat") then {role:"paylasilan-uye",caps:["paylasilan-kaynak"]} else empty end),
       {role:"anon",caps:["public-yuzey"]} ]) end)
| .theory.trust_boundaries = (if ((.theory.trust_boundaries // [])|length)>0 then (.theory.trust_boundaries) else
    ([ (if has("user|account|profile|/me|/orders|/transactions") then {name:"cross-user",from:"userA",to:"userB-data",control:"ownership",weight:4} else empty end),
       (if has("tenant|org|workspace|team") then {name:"cross-tenant",from:"t1",to:"t2-data",control:"tenant_id",weight:5} else empty end),
       (if has("upgrade|billing|/plan|premium|/pro|subscription|paywall") then {name:"plan-gate",from:"free",to:"paid-feature",control:"subscription",weight:3} else empty end),
       (if (has("/v1") and has("/v2")) or has("/api/v[0-9]") then {name:"version-drift",from:"v-eski",to:"v-yeni",control:"tutarli-authz",weight:4} else empty end),
       (if has("/admin|/manage|role|privilege") then {name:"privilege",from:"low-role",to:"admin-action",control:"role-check",weight:5} else empty end) ]) end)
| .theory.critical_flows = (if ((.theory.critical_flows // [])|length)>0 then (.theory.critical_flows) else
    ([ (if has("transfer|payment|payout|/send|/pay") then {name:"transfer-odeme",endpoints:["?"],assumptions:["amount>0","recipient_exists","balance>=amount","idempotent"]} else empty end),
       (if has("login|/auth|signin|session|token|oauth") then {name:"auth-login",endpoints:["?"],assumptions:["rate-limited","reset-token-tahminsiz","oauth-state-dogrulanir"]} else empty end),
       (if has("register|signup") then {name:"signup",endpoints:["?"],assumptions:["email-dogrulanir","race-yok"]} else empty end),
       (if has("reset|forgot|recover") then {name:"password-reset",endpoints:["?"],assumptions:["token-tek-kullanim","token-IDOR-yok"]} else empty end),
       (if has("upload|/file|/media|import") then {name:"upload-import",endpoints:["?"],assumptions:["tip-uzanti-dogrulanir","yol-kontrolu"]} else empty end) ]) end)
| .theory.developer_profile = ((.theory.developer_profile // {}) + {
    stack:(((.theory.developer_profile.stack) // tech) | if .=="" then "?" else . end),
    corners_likely:(.theory.developer_profile.corners_likely //
      ([ (if (has("/v1") and has("/v2")) then "v1/v2 authz drift" else empty end),
         (if has("oauth|sso") then "oauth sonradan eklenmis olabilir" else empty end),
         (if has("payment|stripe|billing") then "odeme 3.parti webhook/dogrulama zayif olabilir" else empty end),
         (if has("graphql") then "graphql introspection/derin sorgu" else empty end) ])) })
| .theory.open_questions = (if ((.theory.open_questions // [])|length)>0 then (.theory.open_questions) else
    ([ (.theory.trust_boundaries[]? |
          if .name=="cross-user" then {q:"userA userB verisini/islemlerini gorebilir/degistirebilir mi?",boundary:"cross-user",impact:4,state:"open"}
          elif .name=="cross-tenant" then {q:"tenant1 tenant2 verisine erisebilir mi (tenant_id manipulasyonu)?",boundary:"cross-tenant",impact:5,state:"open"}
          elif .name=="plan-gate" then {q:"free kullanici parali/premium endpoint cagirabilir mi?",boundary:"plan-gate",impact:3,state:"open"}
          elif .name=="version-drift" then {q:"v1 eski authz yi v2 kadar zorluyor mu?",boundary:"version-drift",impact:4,state:"open"}
          elif .name=="privilege" then {q:"dusuk-rol admin aksiyonunu method/endpoint ile tetikleyebilir mi (BFLA)?",boundary:"privilege",impact:5,state:"open"}
          else empty end),
       (.theory.critical_flows[]? |
          if (.name|test("transfer")) then {q:"transfer akisi negatif/asiri amount, replay, race e dayanikli mi?",boundary:"business_logic",impact:5,state:"open"}
          elif (.name|test("reset")) then {q:"reset token tahmin/IDOR/tek-kullanim atlatmaya acik mi?",boundary:"auth",impact:5,state:"open"}
          else empty end) ]) end)
JQ

jq -f "$PROG" "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
rm -f "$PROG"

echo "TEORI KURULDU: $(jq -r '.theory.purpose' "$SURF")"
jq -r '"  varlik="+((.theory.value_assets//[])|map(.asset)|join(","))+"  sinir="+((.theory.trust_boundaries//[])|map(.name)|join(","))+"  akis="+((.theory.critical_flows//[])|map(.name)|join(","))' "$SURF"
echo "  ACIK SORULAR ($(jq -r '[.theory.open_questions[]?|select(.state=="open")]|length' "$SURF")) - avcinin cevaplayacagi:"
jq -r '[.theory.open_questions[]?|select(.state=="open")][0:6][] | "    - ["+(.boundary)+" x"+(.impact|tostring)+"] "+.q' "$SURF"
echo "  (model: data-flow-and-mental-model.md ile bu teoriyi DOLDUR/keskinlestir; reason_hypotheses bundan test uretir.)"
