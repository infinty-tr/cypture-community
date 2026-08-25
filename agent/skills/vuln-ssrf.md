---
name: vuln-ssrf
description: >
  Sunucunun kullanıcı-kontrollü bir URL/host'a giden HTTP isteği yaptığı yerlerde uygulanır
  (url/fetch/webhook/import/proxy alanı). İç ağa veya cloud metadata'ya pivot ettirir.
  Ana karar: istek gerçekten sunucudan mı çıkıyor — OOB callback / metadata yanıtı / iç servis farkı var mı.
---

# 🌐 SSRF (Server-Side Request Forgery) — sunucuya senin seçtiğin hedefe istek yaptır

> **Tek cümle:** Bir URL alanı sunucu tarafında fetch ediliyorsa, önce kendi OOB sunucunla "istek bizden çıkıyor mu" diye kanıtla, sonra iç hedeflere (metadata, localhost, iç IP) pivot et.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE sunucunun bir hedefe giden istek yaptığı alanlarda test et:
  - `url=`, `image_url`, `webhook`, `callback`, `fetch`, `import`, `proxy`, `feed`, `redirect_uri` (server-side), PDF/screenshot/thumbnail render, SSO metadata URL.
- YOKSA: "SKIP: sunucu giden istek yapmıyor; salt client-side fetch/redirect ise bu sınıf uygulanmaz."

## 2. İNSAN MUHAKEMESİ
- Sunucu, kullanıcının verdiği URL'i kendi ağ konumundan açıyor. Bu sunucu genelde iç servisleri ve cloud metadata endpoint'ini görebilir — attacker göremez.
- Geliştirici hedefi validate etmemiş veya sadece scheme/host blacklist'ine güvenmiş olabilir (DNS rebinding, redirect, IP-encoding ile aşılır).
- Asıl mesele: fetch SUNUCUDAN mı çıkıyor (SSRF) yoksa tarayıcıdan mı (sadece açık-redirect/CSRF). Karar [[data-flow-and-mental-model]] ile verilir: veri akışı server-side mı.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Meşru, harici bir URL ver (kendi kontrolündeki normal sayfa); status/timing/gövdeyi not al. request_id sakla.
- **Tek prob (OOB ile varlık kanıtı):** URL alanına unique collaborator host koy:
  ```
  url=http://<UNIQUE>.oob-host.tld/x
  ```
  Kaynak IP'si hedefe ait DNS+HTTP callback geldi mi izle. Bu "istek sunucudan çıkıyor" kanıtıdır.
- **İç hedef probu (callback doğrulandıktan SONRA):** Cloud metadata:
  ```
  url=http://169.254.169.254/latest/meta-data/
  ```
  Yanıtta metadata listesi/dizini döndü mü; localhost/iç IP için yanıt/timing farkına bak.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Hedef IP'den OOB callback; VEYA `169.254.169.254` yanıtında metadata anahtarları; VEYA `localhost`/iç-IP probunda harici hedeften FARKLI status/timing/içerik (kapalı port vs açık servis ayrımı).
- **Gürültü (sinyal DEĞİL):** Salt 200 / WAF / "invalid url"; tüm hedeflerde aynı jenerik hata (fetch hiç yapılmıyor olabilir); kendi tarayıcı trafiğin.

## 5. DOĞRULAMA KAPISI (kanıt)
- OOB callback'in kaynak IP'si hedef altyapıya ait olmalı; unique subdomain ile karıştırma yok. Negatif kontrol: alanı boş bırakınca callback YOK.
- İç fark: `http://127.0.0.1:<kapalı-port>` vs `<açık-port>` farklı davranmalı (timing/banner) → iç ağ erişimi kanıtı.
- **Bağlam zinciri (kanıtla, varsayma):** SSRF → `169.254.169.254/latest/meta-data/iam/security-credentials/<rol>` → geçici IAM credential. Credential'ı SADECE göster/maskele; gerçekten döndüyse bu kritik kanıt. request_id'leri yaz.

## 6. VARYASYON / BYPASS (bloklanınca)
- **IP-format ekseni:** Decimal (`2130706433`), oktal, IPv6 (`[::1]`, `[::ffff:169.254.169.254]`), `0.0.0.0`.
- **Redirect ekseni:** Kendi sunucun 302 ile iç hedefe yönlendirsin (host whitelist'i atlatır).
- **DNS ekseni:** DNS rebinding — TTL düşük A kaydı önce dış sonra iç IP.
- **Scheme/sink ekseni:** `gopher://` (raw TCP, iç Redis/HTTP), `file://`, `dict://`; metadata için bulut sağlayıcıya göre header (`Metadata-Flavor: Google`) gerekebilir.
- **Encoding ekseni:** `@`, ek nokta, unicode host bypass. Sinyal/OOB yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Client-side redirect'i / açık-redirect'i SSRF sanmak. Tarayıcı yönlenmesi server-side fetch DEĞİL — collaborator hit hedef IP'den gelmedikçe SSRF yok.
- Yansıyan URL string'ini "fetch edildi" sanmak.
- `169.254.169.254`'e bağlanamayıp dönen jenerik timeout'u "metadata erişimi" sanmak.
- Collaborator'a kendi test trafiğini callback sanmak — kaynak IP doğrula.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Hedef IP'den OOB callback (negatif kontrol temiz) VEYA metadata/iç servis yanıtı doğrulandı; IAM zinciri varsa kanıt maskeli.
- **Sinyal yok, kapat:** Tüm hedeflerde aynı jenerik hata, callback yok, tüm encoding/redirect varyasyonları boş → fetch yapılmıyor.
- **Şüpheli, ilerle:** Harici URL'de callback var ama iç hedefler bloklu (SSRF doğrulandı, iç erişim filtreli) → redirect/DNS-rebinding/IP-format eksenine devam.

## ÖZET — 5 KURAL
1. Giden istek server-side değilse SKIP — client redirect'i SSRF sanma.
2. Önce OOB ile "sunucudan çıkıyor mu" kanıtla; SONRA iç hedeflere pivot et (blind SSRF → OOB).
3. 200/WAF/echo KANIT DEĞİL — hedef-IP callback / metadata yanıtı / iç fark bulgudur.
4. İç erişimi açık vs kapalı port farkıyla doğrula; metadata→IAM zincirini kanıtla, uydurma.
5. Bloklanınca IP-format, redirect, DNS-rebinding, gopher/scheme, encoding eksenlerini dene; boşsa kapat.
