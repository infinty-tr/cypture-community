---
name: vuln-host-header-injection
description: >
  Uygulama gelen Host / X-Forwarded-Host header'ının TÜM değerine güvenip
  link/yönlendirme/cache anahtarı/routing kararı kuruyorsa uygulanır.
  Reset-link zehirleme, web-cache poisoning, routing-based SSRF, vhost confusion
  dener. Ana karar: kontrol ettiğim Host değeri somut bir impact'e mi dönüşüyor?
---

# 🏠 HOST HEADER INJECTION — uygulama Host'a güvenip link/cache/route kuruyorsa açıktır

> **Tek cümle:** Host/X-Forwarded-Host'un TÜM değerini saldırgan domain'iyle değiştir; kanıt byte enjeksiyonu değil, üretilen link/cache yanıtı/route kararının senin host'unu BİREBİR taşımasıdır.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[chain-attack-builder]] [[data-flow-and-mental-model]] [[request-economy]] [[vuln-crlf-header-injection]] [[vuln-cache-poisoning-deception]] [[vuln-ssrf]] [[vuln-open-redirect]] [[attacker-mindset-and-persistence]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Uygulama Host header'ının değerine güvenip bir karar/çıktı üretiyorsa:
  - Password-reset / e-posta doğrulama / davet linki Host'tan kuruluyor (reset poisoning → hesap ele geçirme).
  - Mutlak URL / canonical tag / `<base href>` / absolute redirect Host'tan üretiliyor.
  - Önde cache/CDN var ve cache-key Host'u dışlıyor ya da karıştırıyor (web-cache poisoning, cache-key confusion).
  - Ters proxy Host/X-Forwarded-Host'a göre upstream'e route ediyor (routing-based SSRF, vhost confusion).
- SKIP: tek mesele Host değerine CRLF (`%0d%0a`) byte enjeksiyonu ise → bu BYTE injection, [[vuln-crlf-header-injection]]. Bu skill header'ın TÜM değerini kontrol etmekle ilgilidir, satır kırmakla değil.

## 2. İNSAN MUHAKEMESİ
- Geliştirici "Host her zaman benim domain'imdir" varsaymış; reset linkini `https://<Host>/reset?token=...` ile kuruyor. Ama Host istemci-kontrollü bir header'dır.
- Proxy/CDN mimarisinde sorumluluk dağılır: backend `X-Forwarded-Host`'a, edge ise gerçek `Host`'a bakar — aradaki güven farkı injection yüzeyidir. Cache-key'in hangi header'ları içerdiği kritik.
- Asıl mesele: Host'un yanıta yansıması TEK BAŞINA exploit değil; impact = reset linki attacker'a gitti / zehirli yanıt başkasına servis edildi / istek iç hedefe route edildi. Hangi katmanın (app/edge/proxy) hangi header'a güvendiğini düşün.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Normal `Host` ile istek; üretilen link/`Location`/canonical/cache durumunu (`Age`, `X-Cache`) not al. request_id sakla.
- **Kademeli prob:**
  1. `Host: <hedef-evil>` → üretilen link/`Location`/canonical `<hedef-evil>` aldı mı? Yansıdıysa ama erişemiyorsan reset akışını ara.
  2. Gerçek Host'a dokunma, `X-Forwarded-Host: <hedef-evil>` (ve `X-Host`, `X-Forwarded-Server`, `Forwarded: host=`) ekle → çıktı değişiyor mu? Çoğu app sadece bunlara güvenir.
  3. Duplicate Host / absolute-URI request line (`GET https://<hedef-evil>/ HTTP/1.1` + `Host: <hedef>`) → hangi katman hangisini okuyor.
  4. Cache: zehirli Host ile yanıtı doldur, sonra TEMİZ istekle aynı kaynağı çek → cache HIT zehirli mi geldi (cache-key Host'u dışlıyor mu)?
  5. Routing/SSRF: Host'u iç servis adıyla değiştir (`Host: internal-admin`) → farklı upstream/iç içerik döndü mü.
- **Cypture notu:** `cyp_send_request` ile ham yanıtı ve üretilen link'i al; `cyp_compare_requests` ile baseline ↔ prob çıktısını diff'le; `X-Cache`/`Age` ile cache HIT'i doğrula.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Reset/doğrulama linki, `Location`, canonical veya `<base href>` saldırgan Host'u BİREBİR içeriyor; VEYA zehirli yanıt temiz istekte cache HIT olarak dönüyor; VEYA Host değişimi farklı upstream/iç içerik route ediyor.
- **Gürültü (sinyal DEĞİL):** Host'un sadece sayfa gövdesinde text olarak yansıması (link kurmuyor); 400/"invalid host" reddi; değişikliğin hiçbir çıktıya yansımaması; framework'un Host'u kendi config domain'iyle override etmesi (sanitize).

## 5. DOĞRULAMA KAPISI (kanıt)
- **Reset poisoning:** reset/davet akışını tetikle, e-posta/yanıttaki link'in `<hedef-evil>` taşıdığını somut akışla göster; negatif kontrol: meşru Host'ta link doğru domain. Impact = token attacker host'a gider → hesap ele geçirme. request_id'ler.
- **Cache poisoning:** zehirli yanıtın ikinci (temiz, farklı oturum) istekte `X-Cache: HIT` olarak döndüğünü göster → [[vuln-cache-poisoning-deception]].
- **Routing/SSRF:** Host/X-Forwarded-Host ile iç hedefe ulaşıldığını (farklı/iç içerik, iç IP yanıtı) kanıtla → [[vuln-ssrf]].
- **vhost confusion:** edge ↔ backend farklı Host okuyup yetkisiz vhost'a erişim sağladığını göster. Her iddia baseline + tetikleyici request_id ile.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Header ekseni:** `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=`, `X-Original-Host`, duplicate `Host`, absolute-URI request line.
- **Değer ekseni:** `<hedef>.evil.com`, `evil.com#<hedef>`, `<hedef>@evil.com`, port ekleme (`<hedef>:1337`), iç isim (`localhost`, `internal-admin`, iç IP), boşluk/tab varyantları.
- **Akış ekseni:** Reset yoksa e-posta doğrulama / davet / fatura / paylaşım / "share link" gibi başka Host-türevli akışlar; OAuth redirect_uri host'u; canonical/SEO tag.
- **Cache ekseni:** cache-key dışı header ile poisoning, `Vary` zafiyeti, query/param cache-key confusion → [[vuln-cache-poisoning-deception]].
- Sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Host'un gövdede yansımasını "Host injection" sanmak. Link/`Location`/canonical/route/cache impact'i gösterilmedikçe sadece reflection — exploit DEĞİL.
- **CRLF ile karıştırmak:** Bu skill header'ın TÜM değerini kontrol eder; satır kırma (`%0d%0a`) ayrı sınıf → [[vuln-crlf-header-injection]].
- **Reset linkini görmeden poisoning iddia etmek:** linkin gerçekten attacker host'u taşıdığını ve akışın tetiklenebildiğini göstermeden impact yok.
- **Cache HIT'i doğrulamadan poisoning demek:** `X-Cache: HIT` / `Age` artışı / temiz-oturum tekrarı olmadan cache poisoning spekülasyondur.
- **Test aracının Host'u kendi düzeltmesini gerçek davranış sanmak:** hedefin ham yanıtına ve üretilen link'e bak, aracın gönderdiği Host'a değil.
- **"invalid host" reddini bypass sanmak:** 400 reddi koruma çalışıyor demektir, açık değil.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Host saldırgan değeri somut impact'e döndü (reset/davet linki attacker'da / cache HIT zehirli / iç route) + negatif kontrol temiz + tekrarlı.
- **Sinyal yok, kapat:** Host ve tüm forwarded-host varyantları hiçbir link/route/cache çıktısını değiştirmiyor ya da "invalid host" ile reddediliyor.
- **Şüpheli, ilerle:** Host linke yansıyor ama reset akışına erişemiyorsun (reflection var, impact zinciri eksik) → cache/canonical/routing/diğer akış eksenine devam; bütçeyi boşa harcama.

## ÖZET — 5 KURAL
1. Mesele header değerinin TÜMÜ; satır kırma değil → byte injection ise [[vuln-crlf-header-injection]].
2. Host yansıması KANIT DEĞİL — link/Location/canonical/cache/route impact'i şart.
3. Gerçek Host tıkalıysa X-Forwarded-Host ve kardeşlerini dene; çoğu app onlara güvenir.
4. Reset/cache/route iddiasını negatif kontrol + (cache için) `X-Cache: HIT` ile bağla.
5. Her kanıt = baseline request_id + tetikleyici request_id; "invalid host" reddini açık sayma.
