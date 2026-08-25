#!/usr/bin/env bash
set -uo pipefail
TARGET="${1:?hedef gerekli}"
WS="${2:-targets/$TARGET}"
D="$(cd "$(dirname "$0")" && pwd)"
PORT="${CYP_PORT:-}"
PORTNOTE="${PORT:+ Hedefe $PORT portundan git (cyp_send_request port=$PORT).}"
CREDSNOTE="${CYP_TEST_CREDS:+ 🔑 OPERATÖR TEST KİMLİĞİ ile Cypture üzerinden login ol (curl-direct YASAK) → cyp_create_replay_session → AUTHENTICATED yüzeyi test et (IDOR/BOLA/yetki yükseltme/iş-mantığı/mass-assignment); birden çok kimlik varsa her birine ayrı session + A-vs-B yetki testi (cyp_list_sessions/cyp_diff_requests). Login JS/SPA ise cyp_browser_navigate. KİMLİK: $CYP_TEST_CREDS}"

bash "$D/wave_state.sh" record "DALGA1-KESIF" "recon: subdomain + endpoint + teknoloji keşfi" >/dev/null 2>&1 || true
NONSEED=$(jq -r '[(.assets[]? | select(.seeded != true)), (.endpoints[]? | select(.seeded != true))] | length' "$WS/surface.json" 2>/dev/null || echo 0)
if [ "${NONSEED:-0}" -gt 0 ]; then
  printf '💡 DALGA 1 — KEŞİF: surface.json gerçek recon içeriyor (%s seed-dışı öğe) → recon ATLANDI.\n' "$NONSEED"
else
  RECON_H=$(bash "$D/spawn_agent.sh" recon-agent "Hedef: $TARGET${PORT:+ (port $PORT)}. subfinder/crt.sh ile subdomain enumeration'ı FİİLEN çalıştır; bulunan her host'u cyp_send_request ile CANLI doğrula ve $WS/urls.txt'e ekle. Her endpoint/parametre/form/teknolojiyi keşfet. Yüzeyi $WS/surface.json ve $WS/urls.txt'e yaz. Kısa envanter özeti döndür.")
  : # recon arka planda — DALGA 2 wait'inde beklenir
fi

bash "$D/wave_state.sh" done "DALGA1-KESIF" >/dev/null 2>&1 || true

bash "$D/load_skills.sh" "$WS/surface.json" ALL >/dev/null 2>&1 || true

bash "$D/wave_state.sh" record "DALGA2-TEST" "web+api+fuzz paralel temel test" >/dev/null 2>&1 || true
INV="Envanteri $WS/surface.json ve $WS/urls.txt'ten, peer bulgularını /cyp/findings.ndjson'dan oku (tekrarlama, zincirle). ÖNCE OKU: /cyp/state.json — önceki dalgalarda ne yapıldı; AYNI host/sınıfı SIFIRDAN tekrar test etme. ZORUNLU oku: $WS/playbook.md (seçili playbook'lar + sözleşmeler). KRİTİK: ezber listeyle YETİNME — hunter-intuition + business-logic-reasoning + response-manipulation'a göre KENDİ hacker mantığınla da düşün: 'geliştirici neyi varsaydı? tersini dene' + İŞ-MANTIĞI kusurları (fiyat/miktar/negatif, akış atlama, race, kupon istismarı) + RESPONSE/CLIENT-SIDE manipülasyonu (gizli alan, status yerine gövde, client kontrolünü atla, mass assignment). Mekanik sinyal yok → MANTIKSAL tutarsızlık ara. BULGU YAZIMI (PoC tam olsun): her bulguya request (ham HTTP istek) + response (ham yanıt) + duration_ms KOY — cyp_create_finding üçünü de OTOMATİK ekler; findings.ndjson'a elle yazıyorsan da koy (eksikse PoC reproduce edilemez ve validate_finding REDDEDER). TEHDİT MODELİ (ezberi bırak): ÖNCE bu host için app_model kur (roller, auth sınırları, değer-sink: para/veri/yetki, INVARIANT'lar) → SADECE bu host'a UYGULANABİLİR sınıfları (class_select/playbook'taki) test et — alakasız endpoint'e alakasız payload PÜSKÜRTME; 'X olabilir' değil 'şu invariant'ı şöyle kırdım'. KANIT KAPISI (ZORUNLU): bir bulgu medium+ VEYA doğrulanmış olabilmek için MOTOR-ÖLÇÜLÜ kanıt şart → cyp_set_baseline + cyp_diff_requests ile GERÇEK fark (status/length/body) ya da OOB hit göster; kanıt yoksa backend onu OTOMATİK info yapar ve doğrulandı DEMEZ (abartı/yalan boşuna, severity'yi kanıt belirler). KAPSAM: her CANLI host en az baseline prob alır, hiçbiri atlanmaz. TAKILMA: motor CYP-DUPLICATE uyarısı verirse aynı isteği BIRAK, FARKLI dene ya da bu hostta bitir.$PORTNOTE$CREDSNOTE"
HW1=$(bash "$D/spawn_agent.sh" web-test-agent "$INV ODAK: ENJEKSİYON — SQLi/NoSQLi, XSS(reflected/stored/DOM), LFI/path-traversal, SSRF, SSTI, XXE, command injection, CRLF. HER param'da 1=1 vs 1=2 / cyp_set_baseline+cyp_diff_requests ile doğrula. Bulgu → cyp_create_finding + /cyp/findings.ndjson (poc+request+response). 1 bulguyla durma.")
HW2=$(bash "$D/spawn_agent.sh" web-test-agent "$INV ODAK: ERİŞİM/YETKİ + istemci — IDOR/BOLA, BFLA, auth-bypass, CSRF, open-redirect, CORS, clickjacking, cookie-flags. İki-kimlik A/B authz kıyası. Bulgu → cyp_create_finding + /cyp/findings.ndjson.")
HW3=$(bash "$D/spawn_agent.sh" web-test-agent "$INV ODAK: İŞ-MANTIĞI + response/client manipülasyonu — fiyat/miktar/negatif, akış/adım atlama, mass-assignment (yanıt alanını isteğe geri enjekte), gizli/disabled alan, race sinyali, sahiplik karıştırma. MANTIKSAL tutarsızlık ara. Bulgu → cyp_create_finding + /cyp/findings.ndjson.")
HA=$(bash "$D/spawn_agent.sh" api-test-agent "$INV API/auth: BOLA/BFLA/Mass Assignment/JWT/OAuth/GraphQL/rate-limit, iki-kimlik authz. Bulgu → /cyp/findings.ndjson + cyp_create_finding.")
HF=$(bash "$D/spawn_agent.sh" fuzzing-agent "$INV Tech-aware içerik/parametre/dizin keşfi. Yeni endpoint → $WS/urls.txt. Sinyalde /cyp/findings.ndjson + cyp_create_finding.")
bash "$D/wait_agent.sh" ${RECON_H:-} "$HW1" "$HW2" "$HW3" "$HA" "$HF"
bash "$D/wave_state.sh" done "DALGA2-TEST" >/dev/null 2>&1 || true

bash "$D/wave_state.sh" record "DALGA2x-DERINLES" "her canlı host derinlemesine (host x sinif)" >/dev/null 2>&1 || true

HPR="${CYP_DEEPEN_HOSTS_PER_ROUND:-4}"; [ "$HPR" -ge 1 ] 2>/dev/null || HPR=4
DEEPENED="$WS/.deepened_hosts"; [ -f "$DEEPENED" ] || : > "$DEEPENED" 2>/dev/null || true
r=0
while : ; do
  r=$((r+1))
  bash "$D/wave_finalize.sh" "$WS/surface.json" "" >/dev/null 2>&1 || true
  ALLHOSTS="$( { jq -r '.assets[]?.host' "$WS/surface.json" 2>/dev/null; cat "$WS/.enum_live.txt" 2>/dev/null; } | awk 'NF' | sort -u )"
  NHOSTS=$(printf '%s\n' "$ALLHOSTS" | awk 'NF' | wc -l | tr -d ' ')
  if [ -n "${CYP_DEEPEN_ROUNDS:-}" ]; then DEEPEN_MAX="$CYP_DEEPEN_ROUNDS"
  else DEEPEN_MAX=$(( (NHOSTS + HPR - 1) / HPR + 10 )); fi
  if [ "$r" -gt "$DEEPEN_MAX" ]; then printf '💡 KARAR: derinleş tur tavanı (%s) doldu — duruyor.\n' "$DEEPEN_MAX"; break; fi
  HOSTS=""; n=0
  for h in $ALLHOSTS; do
    grep -qxF "$h" "$DEEPENED" 2>/dev/null && continue
    HOSTS="$HOSTS $h"; printf '%s\n' "$h" >> "$DEEPENED"
    n=$((n+1)); [ "$n" -ge "$HPR" ] && break
  done
  if [ -z "$HOSTS" ]; then printf '💡 KARAR: tüm subdomain'"'"'ler derinlemesine test edildi (%s host) — derinleş tamam.\n' "$NHOSTS"; break; fi
  DONECNT=$(grep -c . "$DEEPENED" 2>/dev/null || echo '?')
  printf '💡 DERİNLEŞ (tur %s · kapsanan %s/%s host): %s\n' "$r" "$DONECNT" "$NHOSTS" "$HOSTS"
  DH=""
  for h in $HOSTS; do
    HH=$(bash "$D/spawn_agent.sh" web-test-agent "$INV ODAK HOST: $h. Bu host'un HER endpoint/parametresini DERİNLEMESİNE test et (yüzeysel geçme; eksik-başlık/sürüm tek başına RAPOR DEĞİL → gerçek etkiye yükselt): SQLi/XSS/LFI/SSRF/SSTI/IDOR/auth-bypass/XXE/cmd-inj/CORS/CSRF + iş-mantığı + response/client-side. Her parametre × her sınıf; varyant/blind/time-based/1=1-vs-1=2/WAF-bypass; sinyali GERÇEK ÇIKARIMA taşı (SQLi→version()/satır, LFI→/etc/passwd, IDOR→başkasının verisi, XSS→çalışan PoC+screenshot). Bulgu → /cyp/findings.ndjson + cyp_create_finding (proof_kind/status/extracted_evidence). AYNI açığı TEKRAR YAZMA — önce peer /cyp/findings.ndjson'u oku, varsa atla.")
    DH="$DH $HH"
    HA2=$(bash "$D/spawn_agent.sh" api-test-agent "$INV ODAK HOST: $h. API/auth yüzeyini DERİN test et: BOLA/BFLA/Mass Assignment/JWT/OAuth/GraphQL/rate-limit, iki-kimlik authz, gizli/iç endpoint. Bulgu → cyp_create_finding. AYNI açığı tekrar yazma — peer findings'i oku.")
    DH="$DH $HA2"
  done
  [ -n "$DH" ] && bash "$D/wait_agent.sh" $DH
done

bash "$D/wave_state.sh" done "DALGA2x-DERINLES" >/dev/null 2>&1 || true
bash "$D/wave_finalize.sh" "$WS/surface.json" "" >/dev/null 2>&1 || true

bash "$D/gate-agent.sh" || true
bash "$D/wave_state.sh" record "DALGA3-RAPOR" "dogrulama + CVSS + zincir + rapor" >/dev/null 2>&1 || true
HVAL=$(bash "$D/spawn_agent.sh" validator-agent "/cyp/findings.ndjson'daki verified:false / probable / düşük-güven bulgular senin kuyruğun. Her birini ADVERSARIAL doğrula (correspondence: iddia edilen kanıt yanıtta LİTERAL geçiyor mu; control-diff: baseline'ı 2x cyp_compare_requests; reproduce ≥4/5) — çürütülürse verify_note'a gerekçe yaz. Gerçekse IMPACT'i tavana çıkar (bash scripts/exploit_gate.sh ile tavan al; medium→high→critical KANITLA). Zincirlenebilir bulguları (IDOR+XSS→ATO, SSRF→IMDS, LFI→config→auth) GERÇEK isteklerle birleştir. Sonucu cyp_create_finding + /cyp/findings.ndjson. 'Muhtemelen gerçek' YASAK.")
bash "$D/wait_agent.sh" "$HVAL"
H=$(bash "$D/spawn_agent.sh" reporter-agent "Tüm /cyp/findings.ndjson bulgularını DOĞRULA (false-positive ele), CVSS 3.1 ver, düşükleri zincirle. Her critical/high için cyp_set_baseline+cyp_diff_requests ile GERÇEK fark (status/length/body) ya da OOB hit ile teyit et → verified:true + verify_note. UYARI: motor diferansiyeli/OOB YOKSA backend verified'ı OTOMATİK geri alır ve bulgu info'da kalır — o yüzden iddia etme, gerçekten diff KOŞTUR. cyp_create_finding + /cyp/findings.ndjson. EN SON /cyp/findings.json'a JSON dizisi yaz.")
bash "$D/wait_agent.sh" "$H"
bash "$D/wave_state.sh" done "DALGA3-RAPOR" >/dev/null 2>&1 || true
