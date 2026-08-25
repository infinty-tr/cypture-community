---
name: vuln-csrf
description: >
  Cross-Site Request Forgery. Durum değiştiren bir istek anti-CSRF token /
  SameSite koruması olmadan cross-site tetiklenebildiğinde uygulanır. Ana karar:
  token zorunlu mu, çıkarınca/değiştirince istek hâlâ kabul ediliyor mu.
---

# 🎭 CROSS-SITE REQUEST FORGERY (CSRF) — kurbanın oturumuyla istek zorlama

> **Tek cümle:** Durum değiştiren bir istek, anti-CSRF token olmadan ve SameSite cookie engeli olmadan **cross-site** tetiklenip sunucuda kabul ediliyorsa zafiyettir — etkisiz/GET-only endpoint değildir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Test et eğer: **durum değiştiren** (şifre/email değişimi, transfer, ayar, silme) istek var, kimlik **cookie** ile taşınıyor (Authorization header değil), ve istek cross-site tekrar üretilebilir.
- Kimlik `Authorization: Bearer`/custom header ile taşınıyorsa (cookie değil), istek salt-okunur/etkisizse, ya da CORS+custom-header zaten cross-site göndermeyi engelliyorsa: **SKIP: cookie-tabanlı state-changing değil.**

## 2. İNSAN MUHAKEMESİ
- Tarayıcı cookie'leri cross-site otomatik gönderir; sunucu isteğin **gerçekten kullanıcının niyeti** olduğunu anti-CSRF token (unpredictable, per-session) veya SameSite cookie ile doğrulamalı. Geliştirici token'ı hiç koymamış, koymuş ama **doğrulamamış**, ya da SameSite'ı `None`/yok bırakmış olabilir.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- Baseline: meşru durum-değiştiren isteği yakala; içinde CSRF token (gizli form alanı / header / body) var mı, set-cookie'de `SameSite=Lax/Strict` mi (`None`/yok mu) gör.
- TEK prob (Cypture send_request): isteği **token'ı tamamen çıkararak** tekrar gönder → 200/başarı + state değişti mi? Değiştiyse güçlü sinyal.
- İkincil problar (tek tek): token'ı **başka kullanıcının/rastgele** değeriyle değiştir; `Referer`/`Origin` başlığını kaldır/değiştir → hâlâ kabul mü; Content-Type'ı `application/json`'dan `text/plain`/form'a çevirip preflight'sız gönderilebilir mi.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** token yokken/yabancı token ile state-changing istek **başarıyla işlendi** (gerçek değişiklik gözlendi), VE cookie `SameSite=None`/yok (cross-site gönderilebilir).
- **Aday DEĞİL:** sadece 200 dönmesi (ama değişiklik olmadı); GET-only/etkisiz endpoint; istek aslında `SameSite=Strict` cookie'ye bağlı (cross-site cookie gitmez); JSON + zorunlu custom header ile korunan endpoint.

## 5. DOĞRULAMA KAPISI (kanıt)
- Kanıt: (a) token'sız istek → **gerçek state değişikliği** (örn. email gerçekten değişti, ikinci bir okuma isteğiyle teyit), (b) negatif kontrol: geçerli oturum ama token doğru → çalışır; token bozuk → eğer hâlâ çalışıyorsa doğrulama yok demektir, (c) SameSite=None/yok teyidi, (d) N≥2 tekrar, request_id'ler kayıtlı.
- PoC: cross-site auto-submit HTML form (cookie `credentials` ile) ile değişikliğin tetiklenebileceğini göster.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Token doğrulama ekseni:** token'ı boş/sil/başka-session değeriyle dene.
- **Method ekseni:** POST→GET method override (`?_method=POST`), method değiştir.
- **Content-Type ekseni:** JSON zorunluysa `text/plain`/`application/x-www-form-urlencoded`'a düşür (simple request, preflight'sız).
- **Header ekseni:** `Referer`/`Origin` kaldır veya whitelist bypass (`Referer: https://evil.com/target.com`).
- **SameSite ekseni:** `Lax` ise top-level GET navigasyonu state değiştiriyor mu.
- Her biri hipotez; kabul yoksa **kapat.**

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **GET-only/etkisiz endpoint'i CSRF sanmak:** state değişmiyorsa CSRF yok.
- **JSON + custom header korumalıyı atlamak:** zorunlu `X-Requested-With`/custom header cross-site eklenemez (CORS preflight) → exploit edilemez, rapor etme.
- **SameSite=Lax/Strict'i görmezden gelmek:** cross-site cookie gitmiyorsa CSRF pratikte çalışmaz.
- **Token yansıyor diye korumalı saymak:** token gönderiliyor ama sunucu doğrulamıyorsa hâlâ açık — doğrulamayı test et.
- **Self-CSRF / login-CSRF**'i etkili sanmak: kullanıcı etkisi yoksa düşük.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** token'sız/yabancı-token ile gerçek state değişti + SameSite gönderime izin veriyor + N tekrar + negatif kontrol.
- **Sinyal yok, kapat:** token zorunlu ve doğrulanıyor, veya SameSite=Strict/Lax cross-site cookie'yi kesiyor, veya custom-header koruması var.
- **Şüpheli, ilerle:** token çıkınca 200 ama değişiklik teyit edilmedi → ikinci okuma isteğiyle doğrula, sonra karar ver.

## ÖZET — 5 KURAL
1. Sadece **cookie-tabanlı state-changing** istekte test et.
2. Token'ı **çıkar/boz**, gerçek state değişikliğini teyit et (sadece 200 değil).
3. SameSite (`None`/yok) ve cross-site cookie gönderimini doğrula.
4. JSON+custom-header ve SameSite=Strict korumalıyı atlama — exploit edilemez.
5. GET-only/etkisiz endpoint'i CSRF sayma.
