---
name: vuln-cache-poisoning-deception
description: >
  Bir CDN/cache katmanı varken uygulanır. Poisoning: unkeyed bir input (örn.
  X-Forwarded-Host) yanıtı etkileyip cache'leniyor ve başka kullanıcılara servis
  ediliyorsa. Deception: duyarlı bir sayfa statik-uzantı/path hilesiyle cache'lenip
  başkasına okutulabiliyorsa. Ana karar: zehirli/duyarlı yanıt gerçekten saklandı mı.
---

# 🗃️ WEB CACHE POISONING & DECEPTION — unkeyed input ile cache'i silahlandırma

> **Tek cümle:** Cache anahtarına girmeyen bir input yanıtı değiştirip saklanıyorsa (poisoning) ya da duyarlı bir sayfa cache'lenecek gibi gösterilip başkasına servis ediliyorsa (deception), tek istekle çok kurban etkilenir — kanıt SAKLANMADIR, yansıma değil.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[chain-attack-builder]] [[vuln-crlf-header-injection]] [[vuln-xss]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE araya bir **cache** giriyorsa: `Age`, `X-Cache: HIT/MISS`, `CF-Cache-Status`, `X-Served-By`/`X-Cache-Hits`, `Via`, `Cache-Control: public`/`s-maxage` header'ları görünüyor.
- **Poisoning için:** yanıtta yansıyan host/scheme/path bağımlı içerik (absolute URL, redirect `Location`, `<script src>`, `<base href>`, canonical, open-redirect parametresi) — yani unkeyed bir input çıktıya gömülüyor.
- **Deception için:** cookie/session ile render olan **duyarlı** sayfa (account, profile, API key/CSRF token gösterimi, sipariş geçmişi) + cache'in uzantı/path bazlı kuralı.
- SKIP: cache yok / her yanıt `private`+`no-store` / sadece tamamen statik dosyalar / yansıyan input cache-key'e dahil (keyed).

## 2. İNSAN MUHAKEMESİ
- Cache anahtarı genelde method+host+path+(bazı) query; ama uygulama `X-Forwarded-Host`/`X-Forwarded-Scheme` gibi **unkeyed** header'ı yanıta gömerse → bir kez zehirle, anahtar eşleşen herkese servis edilir. Kilit kavram: input yanıtı etkiliyor AMA cache anahtarına girmiyor (unkeyed).
- **Cache deception**'da geliştirici/CDN "`.css`/`.js` istek = statik, cache'le" kuralı koyar; origin ise path traversal/uzantı yorumuyla (`/account.css` → `/account`) duyarlı sayfayı verir → public cache'e duyarlı veri girer ve saldırgan onu okur.
- Asıl mesele her ikisinde de SAKLANMA + SCOPE: yanıt cache'e girdi mi, ve o cache girişi BAŞKA bir kullanıcıya servis ediliyor mu (aynı anahtar, paylaşılan/public cache)?

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Normal istek gönder (`cyp_send_request`), `Age`/`X-Cache`/`CF-Cache-Status`/`Cache-Control` ve yansıyan host/path davranışını kaydet. **Cache-buster disiplini:** her prob'a benzersiz `?cb=<rand>` ekle ki MISS alıp kendi cache girişini izole edesin — başkasının cache'ini kirletme.
- **Poisoning kademeli prob:**
  1. Cache-buster'lı path'e TEK unkeyed header ekle (`X-Forwarded-Host: <hedef-evil>`) → yanıtta yansıdı mı (absolute URL/redirect/script-src değişti mi)?
  2. Yansıdıysa AYNI cache-buster'lı path'i 2. kez **header'sız** çek → zehir `X-Cache: HIT` olarak geri geldi mi (anahtarda saklandı = unkeyed kanıtı)?
  3. `Age` artıyor + N tekrar HIT → kalıcı saklanma.
- **Deception kademeli prob:** `/account` yerine `/account.css` (veya `/account/x.css`, `/account;.css`, `/account%2e%2e/x.js`) iste → duyarlı içerik 200 döndü mü VE yanıt cacheable mı (`Cache-Control: public`/CDN HIT)? İdeal teyit: aynı path'i farklı/oturumsuz istekle çekip duyarlı verinin saklı geldiğini gör.
- **Fat-GET / parameter cloaking:** GET'e body veya yinelenen/cloaked parametre (`?param=keyed&param=evil`, `;param=`) ekleyip unkeyed kalan kısmı yanıta sızdır.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (poisoning):** Unkeyed header/param yansıması + ikinci (header'sız) buster'lı istekte `X-Cache: HIT` ile zehir geri döndü (kanonik anahtarda saklandı) + `Age` ilerliyor.
- **Aday (deception):** Sahte-uzantılı/traversal path duyarlı veriyi döndürüyor + yanıt cacheable (public/HIT) + oturumsuz/ayrı istekte aynı duyarlı veri geldi.
- **Gürültü:** Yansıma var ama cache'lenmiyor (her seferinde MISS, `private`/`Age:0`); cache-buster'lı yanıtı poisoning sanmak; WAF/CDN 403 error sayfası; `Age` var ama HIT'te zehir YOK; deception'da 200 ama veri public/duyarsız.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Poisoning:** (1) inject request_id, (2) **header'sız/temiz** istekle zehrin HIT döndüğü request_id, (3) N tekrar HIT + `Age` ilerleyişi, (4) negatif kontrol: farklı buster path zehirsiz baseline döner. Scope kanıtı: zehrin paylaşılan/public anahtarda (kullanıcıya özel değil) saklandığını göster — yoksa sadece kendi cache'in.
- **Deception:** (1) sahte-uzantı duyarlı yanıt request_id, (2) ikinci/HIT isteğinde aynı duyarlı veri saklı geldi, (3) ideal: attacker (oturumsuz) ile victim verisinin okunduğu gösterim, (4) negatif: normal `/account` cache'lenmiyor.
- **Disiplin:** Yıkıcı/kalıcı zehir yerleştirme; mümkünse benzersiz cache-buster ile İZOLE girişe zehir koy, zararsız ayırt edici marker kullan, gerçek paylaşılan cache'i kirletmekten kaçın. request_id'leri yaz.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Unkeyed header ekseni:** `X-Forwarded-Host`, `X-Forwarded-Scheme`/`-Proto`, `X-Host`, `X-Forwarded-Server`, `X-Original-URL`/`X-Rewrite-URL`, `X-Forwarded-Port`, dual `Host`.
- **Parameter cloaking / fat-GET:** body parametresinin unkeyed kalması; yinelenen param (`?cb=1&cb=2`); ayraç farkı (`;`, `&`, `%26`); UTM gibi cache-key'den dışlanan parametreye zehir gömme.
- **Deception uzantıları/path:** `.css/.js/.png/.ico`, `/%2e%2e`, `;.css`, path-param `/x.css`, encoded slash `%2f`, `//`, traversal-then-extension.
- **Cache-key normalizasyonu farkı:** case, trailing slash, port, çift slash, encoded char — origin ile CDN'in farklı normalize ettiği yer (cache key confusion).
- **Header tekrarı / encoding / cache-buster konumu:** dual header, obfuscated değer, `Age`/`X-Cache` davranışına göre HIT zamanlaması.
- Hiçbiri saklanmıyorsa kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Cache-buster'lı yansımayı poisoning sanmak — header'sız temiz istekte HIT olarak saklandığı KANITLANMADAN FP.
- `Age` header'ı var diye "cache'lendi" demek; zehrin HIT olarak GERİ DÖNDÜĞÜNÜ göstermeden olmaz.
- Header yansımasını her zaman cache-key dışı (unkeyed) varsaymak — aslında keyed olabilir; farklı değerlerle ayrı HIT/MISS davranışını test et.
- Deception'da yanıtın gerçekten **public/paylaşılan** cache'e girdiğini değil, sadece 200 döndüğünü görmek; per-user cache zehri başkasına servis edilmez.
- WAF/CDN error/challenge sayfasını "poisoned" sanmak.
- Kendi tarayıcı/browser cache'ini (private) paylaşılan CDN cache sanmak.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Temiz/header'sız istek zehri HIT olarak döndürdü (poisoning, paylaşılan scope) ya da duyarlı yanıt cacheable + saklandı + ayrı oturumda okundu (deception), N tekrar + negatif kontrol tutarlı.
- **Sinyal yok, kapat:** Yansıma cache'lenmiyor / her şey `private`/MISS / cache yok / yansıyan input keyed.
- **Şüpheli, ilerle:** Yansıma var, saklanma belirsiz → §6 eksenleriyle (unkeyed header, cloaking, normalizasyon farkı) cache-key'i zorla.

## ÖZET — 5 KURAL
1. Önce cache var mı: `Age`/`X-Cache`/`CF-Cache-Status` yoksa SKIP.
2. Cache-buster disiplini: her prob'a benzersiz `?cb=` ile izole MISS al, sonra TEK unkeyed header inject et.
3. Asıl kanıt: BUSTER'SIZ/header'sız temiz istekte zehrin HIT dönmesi + `Age` ilerleyişi.
4. Deception'da duyarlı yanıtın gerçekten **public/paylaşılan** cache'e girip ayrı oturumda okunduğunu göster.
5. Saklanma yoksa = yansıma ≠ zafiyet, FP yazma; paylaşılan cache'i gerçekten kirletme.
