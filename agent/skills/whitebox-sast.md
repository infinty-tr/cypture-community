---
name: whitebox-sast
description: >
  GREY-BOX SAST metodolojisi — kaynaktan source→sink taint akışı izle, her savunmasız
  yolu CANLI endpoint'te doğrula. Kaynak BULUR, motor KANITLAR. Dış internetten kaynak
  çekme yasak; yalnız operatörün verdiği $WS/source okunur (bkz. [[core-contract]] 3c,
  önce [[whitebox-source-recon]] ile haritala).
---

# SKILL: Grey-box SAST — Taint & Canlı Doğrulama (whitebox-sast)

> Disiplin: bir SAST "bulgusu" TEK BAŞINA bulgu değildir. Kaynak bir HİPOTEZ verir;
> onu **canlı hedefte** (`cyp_send_request`, baseline'dan ölçülebilir sapma, request_id,
> tekrar) kanıtlamadan "ŞÜPHELİ" kalır. Amaç: false-positive üreten klasik SAST'tan
> kaçınmak — her aday canlı kapıdan geçer.

## AKIŞ: SINK → GERİ İZLE → KAYNAK GİRDİSİ → CANLI PROB → KANIT

### 1. SINK BUL (kaynakta)
İlgili sınıfın tehlikeli çağrısını grep'le (`$WS/source` altında). Sınıf→sink haritası:
- **SQLi:** string-concat/f-string/`Sprintf` ile sorgu, ORM `.raw()`/`.exec()`, dinamik `ORDER BY`.
- **RCE/komut:** `exec/system/popen`, `os/exec.Command` (shell=true / `sh -c`), `child_process.exec`, `eval`.
- **Path traversal/LFI:** dinamik yol ile `open/readFile/ReadFile/include/require`.
- **SSTI:** kullanıcı girdisi → template string (`render_template_string`, `Template(...).render`).
- **SSRF:** kullanıcı URL'si → outbound istek. **Deser:** `pickle/yaml.load/unserialize/ObjectInputStream`.
- **XSS:** sunucu yanıtına escape'siz kullanıcı verisi; `dangerouslySetInnerHTML`, `innerHTML`, `|safe`.

### 2. GERİ İZLE (taint): sink → handler → route → kullanıcı girdisi
Sink'ten parametreye doğru geri yürü. Soru: bu değişken bir HTTP girdisinden mi geliyor
(query/body/header/path/cookie)? Arada **sanitizer/parametrize/allowlist** var mı?
- Parametrize sorgu / prepared statement / ORM binding VARsa → SQLi DÜŞÜK (atla, "SKIP: parametrize").
- `filepath.Clean`+prefix kontrolü / allowlist VARsa → traversal DÜŞÜK.
- Escape/auto-escaping template VARsa → XSS DÜŞÜK.
Mitigasyon yoksa ve girdi sink'e ulaşıyorsa → **aday** (hangi route, hangi parametre?).

### 3. CANLI PROB (motor) — kanıtı burada üret
Her aday için `whitebox-source-recon` route eşlemesini kullan: hangi endpoint + hangi parametre.
- Önce baseline (2-3 kez), sonra sınıfa özel TEK prob (reçete: ilgili `vuln-*` skill'i:
  [[vuln-sqli]], [[vuln-command-injection]], [[vuln-lfi-path-traversal]], [[vuln-ssti]],
  [[vuln-ssrf]], [[vuln-deserialization]], [[vuln-xss]], [[vuln-idor]], [[vuln-bfla]]).
- Kaynak sana BEKLENEN davranışı söyler (ör. "bu param doğrudan `Sprintf`'e giriyor") →
  sapmayı DAHA KESİN ararsın (daha az kör istek, daha yüksek isabet).
- Blind sink (OOB) ise [[oob-blind-confirmation]] / [[out-of-band-testing]].

### 4. KANIT KAPISI (evidence-discipline ile aynı)
Bulgu = HEM kaynak referansı (`file:line` + taint zinciri) HEM canlı kanıt (request_id + sapma).
`cyp_create_finding` + `/cyp/findings.ndjson`. Alanlar:
- `evidence`: canlı request_id'li sapma (zorunlu — asıl kanıt).
- `source_ref`: `path:line` (destekleyici; raporda "Kaynak kanıtı" olarak görünür).
Kaynak doğruladı ama canlı sapma YOKsa (ör. endpoint erişilemez/kod ölü): "ŞÜPHELİ — kaynakta var,
canlı teyit edilemedi" de, CVSS yükseltme. Asla canlı kanıt olmadan "confirmed" deme.

### 5. KAYNAĞIN AVANTAJI (neden grey-box daha iyi)
- Gizli/undocumented endpoint & parametre (kaynakta var, canlı recon'da görünmez).
- Tam sink görünürlüğü → kör payload tüketme yok, sınıf seçimi kesin.
- Mitigasyon'u önceden gör → test etmeye değmeyeni "SKIP" et (token ekonomisi, [[request-economy]]).
- Secret/JWT-secret/default-cred kaynakta → canlı forge ile anında kanıt.
