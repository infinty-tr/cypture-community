---
name: vuln-crlf-header-injection
description: >
  Kullanıcı girdisi bir yanıt header'ına veya dahili yönlendirme/host hesabına aktığında uygulanır.
  CRLF ile yeni header/gövde enjekte edilir; Host/X-Forwarded-Host ile reset linki ya da cache zehirlenir;
  Set-Cookie enjekte edilir, XSS gövdesi açılır. Ana karar: enjekte CRLF gerçekten yeni header üretti mi.
---

# 📨 CRLF / HTTP Header & Host Header Injection — yanıt header'ına satır enjekte et, Host'u zehirle

> **Tek cümle:** Girdi response header'ına veya host hesabına gidiyorsa, `%0d%0a` ile yeni header/gövde üret ya da Host/X-Forwarded-Host'u kontrol edip reset/cache'i zehirle — kanıt yansıma değil, ham yanıtta gerçek yeni header SATIRIDIR.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[chain-attack-builder]] [[vuln-open-redirect]] [[vuln-cache-poisoning-deception]] [[vuln-xss]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE girdi bir header'a / yönlendirmeye / host'a ulaşıyorsa test et:
  - Girdi `Location`, `Set-Cookie`, `Content-Type`, `Refresh`, özel `X-*` gibi bir response header'ında yansıyor (CRLF için). Tipik: `?url=`, `?next=`, `?redirect=`, `?lang=`, `?return=`.
  - Password-reset / e-posta link / canonical URL / absolute link / `Location` `Host` veya `X-Forwarded-Host`'tan kuruluyor (Host injection için).
  - Cache önünde (CDN) host'a duyarlı içerik (cache poisoning zinciri için → [[vuln-cache-poisoning-deception]]).
- YOKSA: "SKIP: girdi header/host/redirect sink'ine ulaşmıyor; salt gövdede yansıyorsa bu sınıf değil → [[vuln-xss]]."

## 2. İNSAN MUHAKEMESİ
- Sunucu kullanıcı girdisini header satırına string olarak koyuyor. CRLF (`\r\n`) filtrelenmemişse satır sonu enjekte edilip yeni header (hatta boş satır sonrası gövde = response splitting) eklenir.
- Host header'ında: app, gönderdiğin `Host`/`X-Forwarded-Host`'a "güvenip" e-posta/reset linkini ondan kuruyor olabilir → link saldırgan domain'ine gider (hesap ele geçirme).
- Asıl mesele: modern framework çoğu CRLF'i strip eder veya header API'si satır-sonu reddeder; gerçek tetik = header yansıması VE satır-sonu'nun ham çıktıda işlenmesi. Yansıma tek başına exploit değil. Hangi katmanın (app/proxy) header yazdığını düşün.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Normal istek; dönen TÜM response header'larını (ham, sıralı) ve redirect davranışını not al. request_id sakla.
- **Kademeli prob (CRLF):** Header'a yansıyan parametreye enjekte et:
  ```
  ?next=/%0d%0aX-Injected:%201
  ```
  Ham yanıtta gerçek bir `X-Injected: 1` header SATIRI oluştu mu (gövdede değil, header bloğunda, `\r\n` ile ayrılmış)?
  1. Olmadıysa encoding varyantı: sadece `%0a`, çift-encode `%250d%250a`, unicode overlong `%E5%98%8A%E5%98%8D`.
  2. Oluştuysa zincir: `Set-Cookie` enjekte (session fixation) ya da çift CRLF + gövde (response splitting → reflected XSS).
- **Kademeli prob (Host):** Reset/link akışında Host'u değiştir:
  ```
  Host: <hedef-evil>            (veya: X-Forwarded-Host: <hedef-evil>)
  ```
  Üretilen link / `Location` / canonical / e-posta `<hedef-evil>` aldı mı.
- **Cypture notu:** `cyp_send_request` ile ham yanıtı al; `cyp_compare_requests` ile baseline header set'i ↔ prob header set'ini diff'le — yeni satır gerçekten yanıtın header bölümünde mi netleşir. `cyp_encode_decode` ile payload encoding varyantlarını üret.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Yanıtın HEADER bölümünde enjekte edilen header gerçekten yeni satır olarak çıktı; VEYA reset linki / `Location` / canonical tag manipüle edilmiş Host'u içeriyor; VEYA enjekte `Set-Cookie` tarayıcıya işleniyor; VEYA cache anahtarına bağlı zehirlenmiş yanıt başkasına servis edilebiliyor.
- **Gürültü (sinyal DEĞİL):** `%0d%0a`'nın `%250d`/literal text olarak yansıması; header'ın gövde içinde text olarak görünmesi; 400/WAF block; Host değişikliğinin hiçbir çıktıya yansımaması; framework'un satırı tek satıra düzleştirmesi (sanitize).

## 5. DOĞRULAMA KAPISI (kanıt)
- **CRLF:** baseline ham header set'i vs prob → SADECE prob'da yeni header satırı. Ham response'un header bölümünü göster; encode değil gerçek `\r\n` ayrımı olmalı. Tekrarla. Response-splitting iddiası için: çift CRLF sonrası enjekte gövdenin tarayıcıda ayrı/yorumlanan içerik olduğunu kanıtla.
- **Host:** değiştirilen Host'un linkte/`Location`'da BİREBİR çıktığını göster; negatif kontrol: meşru Host'ta link doğru domain. Reset için: e-posta/token linkinin attacker host'a gittiğini somut akışla kanıtla (impact = hesap ele geçirme).
- **Cache zinciri:** zehirli yanıtın cache HIT olarak ikinci (temiz) istekte döndüğünü göster → [[vuln-cache-poisoning-deception]].
- **Cookie injection:** enjekte `Set-Cookie`'nin oturum sabitleme/override yaptığını göster. request_id'leri yaz.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Encoding ekseni:** `%0d%0a`, sadece `%0a` (LF-only proxy), `%0d` (CR-only), `%E5%98%8A%E5%98%8D` (unicode CR/LF overlong), çift-encode `%250d%250a`, `\r\n` raw (bazı API'ler), null `%00` ile kesme.
- **Header ekseni:** `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Forwarded-Proto`, `Forwarded`, duplicate `Host`, absolute-URI request line (`GET http://evil/ HTTP/1.1`).
- **Sink ekseni:** `Location` (open-redirect + header split zinciri → [[vuln-open-redirect]]), `Set-Cookie` (session fixation), `Refresh`, cache-key dışı header ile poisoning, çift-CRLF + gövde (XSS → [[vuln-xss]]).
- **Bağlam ekseni:** Reset akışı yoksa e-posta doğrulama / davet / fatura / paylaşım linki gibi başka Host-türevli akışlar; SMTP/log injection için aynı CRLF.
- Sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Yansımayı her zaman exploit sanmak. Parametrenin gövdede ya da encode edilmiş header'da görünmesi CRLF DEĞİL — ham yanıtta gerçek yeni header SATIRI şart.
- Host'un response'a yansımasını otomatik "Host injection" saymak; impact (reset zehirleme / cache / canonical) gösterilmedikçe sadece yansıma.
- `%0d%0a`'nın literal text olarak yansımasını "split oldu" sanmak.
- Open-redirect'i CRLF header injection ile karıştırmak (ayrı sınıf → [[vuln-open-redirect]]).
- Proxy'nin/HTTP-katmanının test aracında satırı bölmesini gerçek injection sanmak — hedefin ham yanıtına bak.
- Reflected XSS'i CRLF response-splitting sanmak; gövdeye doğrudan yansıyorsa o [[vuln-xss]].

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Ham yanıt header bölümünde enjekte satır VAR (tekrarlı); VEYA reset/link/cache/cookie somut impact ile zehirlendi + negatif kontrol temiz.
- **Sinyal yok, kapat:** CRLF strip ediliyor/encode yansıyor, Host hiçbir çıktıyı değiştirmiyor, tüm encoding/header varyasyonları boş.
- **Şüpheli, ilerle:** Host linke yansıyor ama reset akışına erişemiyorsun (yansıma var, impact zinciri eksik) → cache/canonical/diğer Host-türevli akış eksenine devam.

## ÖZET — 5 KURAL
1. Girdi header/host/redirect sink'ine gitmiyorsa SKIP; gövde yansıması → [[vuln-xss]].
2. CRLF için ham yanıtta gerçek yeni header SATIRI ara; Host için linkin attacker domain'ini aldığını göster.
3. Yansıma KANIT DEĞİL — encode/literal/gövde yansıması split sayılmaz.
4. Host injection'ı impact'le (reset zehirleme / cache poisoning / cookie set) + negatif kontrolle bağla.
5. Bloklanınca encoding, alternatif Host header'ları, Location/Set-Cookie/Refresh/cache, alternatif link akışı eksenlerini dene; boşsa kapat.
