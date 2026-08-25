---
name: vuln-open-redirect
description: >
  Open Redirect. Kullanıcı kontrollü bir parametre redirect sink'ine
  (Location header / JS yönlendirme) akıp harici domaine yönlendirdiğinde
  uygulanır. Ana karar: harici domaine 30x/JS gidiş var mı, whitelist atlandı mı.
---

# ↪️ OPEN REDIRECT — uygulama saldırgan domaine yönlendiriyor

> **Tek cümle:** `redirect`/`next`/`url` gibi bir parametre uygulamayı **saldırgan kontrollü harici domaine** yönlendiriyorsa (30x Location veya client-side `location=`) zafiyettir — aynı-site yönlendirme değildir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-ssrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Sink = **redirect**: yanıtta `Location` başlığı ya da client JS `location.href=`/`location.replace()`/`window.open()`/`meta refresh` kullanıcı girdisiyle besleniyor. Tetikleyici parametreler: `redirect`, `next`, `url`, `return`, `returnUrl`, `dest`, `continue`, `goto`, `callback`, `r`, `u`, OAuth `redirect_uri`.
- Parametre redirect sink'ine ulaşmıyor (sadece sayfada text), ya da hedef tamamen sunucu-sabit ve girdi yoksa: **SKIP: redirect sink'i / kullanıcı girdisi yok.**

## 2. İNSAN MUHAKEMESİ
- Uygulama "login sonrası geri dön" gibi nedenlerle hedef URL'i parametreden alır. Geliştirici hedefi **doğrulamamış**, ya da naif whitelist (`startsWith("/")`, "trusted.com içeriyor mu") yazmıştır. Saldırgan phishing / OAuth code-token sızdırma / SSRF (server-side redirect izleniyorsa) için kurbanı güvenilir domainden kendi domainine taşır.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- Baseline: parametreye meşru same-site path ver (`/dashboard`), yanıttaki `Location`'ı / JS davranışını not et. request_id sakla.
- TEK prob (Cypture `cyp_send_request`, **redirect takip etmeden** ham yanıtı al): parametreye benzersiz harici domain ver `url=https://evil-oob.example`. Gözlem: yanıt 30x ve `Location: https://evil-oob.example` (harici) mi, ya da JS o değeri `location`'a atıyor mu.
- İkincil problar (tek tek, host-parsing tuzakları): aşağıdaki §6 listesinden sırayla.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** yanıt 30x + `Location` başlığı **saldırgan domaine** işaret ediyor (host gerçekten harici), ya da client `location` ataması harici host'a gidiyor.
- **Aday DEĞİL:** `Location` aynı-site path (`/dashboard`); harici değer **path olarak** geri ekleniyor (`https://target.com/https://evil.com`); 200 dönüp yönlendirme yok; sadece parametrenin sayfada text yansıması.

## 5. DOĞRULAMA KAPISI (kanıt)
- Kanıt: (a) baseline same-site `Location` vs prob harici `Location` farkı, (b) **host ayrıştırması** — tarayıcının gerçekten gideceği host saldırgan domaini (`@`, `//`, `\` tuzaklarını host'a göre çöz), (c) N≥2 tekrar, (d) negatif kontrol: rastgele harici domain de aynı şekilde yansıyor (sabit değil). request_id'ler kayıtlı.
- **Zincir etkisi:** OAuth `redirect_uri` manipülasyonu `code`/`token`'ı saldırgan domaine taşıyabiliyorsa ATO'ya çıkar; server-side redirect izleniyorsa SSRF'e döner. Zinciri ayrıca kanıtla ([[vuln-ssrf]], OAuth code-leak).

## 6. VARYASYON / BYPASS — LOCATION HOST-PARSING TUZAKLARI (bloklanınca)
Tarayıcı URL'in **authority** (host) kısmını nasıl ayrıştırdığını sömür; her birini tek tek dene ve host'u doğru çöz:
- **`@` (userinfo) ekseni:** `https://target.com@evil.com` → gerçek host **evil.com** (`target.com` userinfo). `https://target.com%40evil.com` (encoded).
- **`//` / scheme-relative:** `//evil.com`, `https://evil.com`, `\/\/evil.com`, `/%2f%2fevil.com`, `/\/evil.com`.
- **Backslash ekseni:** `https:/\evil.com`, `\\evil.com`, `/\evil.com` — bazı parser'lar `\`'ı `/` sayar (tarayıcı vs sunucu farkı).
- **Whitespace/kontrol:** `https://evil.com%09`, `%0d%0a`, `%00`, başta/sonda boşluk; `https:evil.com` (scheme'siz authority).
- **Encoding ekseni:** URL/double-URL encode `%2f%2f`, `%252f`, unicode noktalama (`。` ideographic dot), bidi.
- **Suffix/prefix whitelist bypass:** suffix `target.com.evil.com`, `target.com.attacker.com`; suffix-param `https://evil.com?x=target.com` / `evil.com#target.com` / `evil.com\@target.com`; prefix `https://evil.com/target.com`; substring `https://eviltarget.com`.
- **Tehlikeli scheme:** `javascript:alert(1)` / `data:text/html,...` — redirect XSS'e dönerse [[vuln-xss]].
- **OAuth ekseni:** `redirect_uri` path-traversal / subdomain (`https://target.com.evil.com`) / kayıtlı host'a açık-redirect zinciri ile code sızdır.
- Her biri hipotez; harici gidiş yoksa **kapat.**

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Aynı-site yönlendirmeyi açık sanmak:** `Location: /path` veya yine kendi domainine gidiş zafiyet değil.
- **Host ayrıştırmasını yanlış yapmak:** `https://target.com@evil.com` → gerçek host `evil.com` (AÇIK); `https://evil.com.target.com` → host `target.com` (GÜVENLİ). `@` ve nokta konumunu doğru çöz — bu ikisini karıştırmak en sık FP.
- **Reflection'ı redirect sanmak:** parametre sayfada text olarak görünüyor ama `Location`'a girmiyor.
- **Path-reflection'ı açık sanmak:** `https://target.com/https://evil.com` host hâlâ target.com.
- **Sunucu-tarafı SSRF ile karıştırmak:** open-redirect kullanıcının TARAYICISINI yönlendirir; sunucunun istek yapması ayrı sınıftır ([[vuln-ssrf]]) — ama redirect→SSRF zincirini ayrıca kontrol et.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** 30x `Location` (veya JS) gerçekten saldırgan domaine gidiyor + N tekrar + host ayrıştırması teyitli + negatif kontrol.
- **Sinyal yok, kapat:** harici değer reddediliyor / same-site'a normalize ediliyor / path olarak ekleniyor; tüm host-parsing eksenleri boş.
- **Şüpheli, ilerle:** naif filtre var ama bir host-parsing ekseni kısmen geçiyor → diğer eksenleri dene; OAuth/SSRF zinciri varsa etkiyi yükselt.

## ÖZET — 5 KURAL
1. Sadece **redirect sink'i** (Location/JS) + kullanıcı girdisi varsa test et.
2. Sinyal = 30x/JS gerçekten **harici** saldırgan domaine gidiyor — redirect takip etmeden ham `Location`'a bak.
3. Host'u doğru ayrıştır: `@` (userinfo→host), `//`, `\`, `%2f`, suffix-nokta tuzaklarını çöz; bunu karıştırmak en sık FP.
4. Aynı-site yönlendirmeyi ve path-reflection'ı açık sayma.
5. `@`/`//`/`\`/encoding/suffix bypass'larını sırayla dene; OAuth code-leak ve redirect→SSRF zincirini ayrıca kanıtla.

## DOĞRULAMA — TARAYICI İLE TEYİT
`cyp_browser_navigate` ile payload'lu URL'i yükle; dönen final URL saldırgan-kontrollü host'a indiyse executed_effect kanıtıdır → `cyp_browser_screenshot` al, `path`'i `extracted_evidence`'a yaz (`proof_kind=executed_effect`). Yalnız Location başlığı görüp bırakma; tarayıcının GERÇEKTEN gittiğini göster.
