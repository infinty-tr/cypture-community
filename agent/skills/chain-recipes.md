# SKILL: Somut Saldırı Zincirleri (chain-recipes)
Tek düşük/orta bulguyu bırakma — ZİNCİRLE, etkiyi büyüt. Bulgu çıkınca "bununla daha ne yapabilirim?" diye sor.

## HAZIR ZİNCİRLER (her adımı GERÇEK kanıtla)
- **Bilgi sızıntısı → hesap ele geçirme:** sürüm/teknoloji/iç-IP sızıntısı → bilinen-CVE (vuln-known-cve) ya da default cred → admin.
- **IDOR/BOLA → veri ihlali → ATO:** /users/{id} başkasının verisi → /users/{id}/reset ya da e-posta/parola alanı → mass-assignment ile rol/parola değiştir → ATO.
- **SQLi → kimlik dökümü → admin giriş:** boolean SQLi → UNION/error ile users tablosu → hash/parola → admin panel.
- **SSRF → metadata → bulut creds:** SSRF → 169.254.169.254 (AWS/GCP/Azure metadata) → geçici anahtar → iç servis.
- **Dosya yükleme → RCE:** upload + zayıf tip kontrolü → web-shell ya da deserialization (Telerik RadAsyncUpload).
- **Açık redirect + OAuth → token çalma:** redirect_uri zafiyeti → OAuth code/token saldırgana.
- **XSS → oturum çalma → CSRF:** stored XSS + HttpOnly yok → cookie çal; HttpOnly varsa → admin adına CSRF ile işlem.
- **CORS yanlış yapılandırma → veri çalma:** ACAO yansıması + credentials → kimlikli veriyi cross-origin oku.
- **Method-authz boşluğu (gap_finder) → BFLA:** GET korumalı, POST/PUT değil → yetkisiz yazma.

## KURAL
- Zincirin HER halkasını ayrı request_id ile KANITLA (uydurma yok). Halka kanıtlanmazsa zincir OLASI/TEORİK.
- `scripts/propagate_finding.sh` ile çalışan deseni diğer host/endpoint'lere yay; `scripts/chain_suggest.sh` öner.
- Önce ESKALASYON (etki büyüt) sonra yeni-bulgu genişliği — bir SQLi'yi dök, 5 ayrı düşük bulgu arama.
