---
name: vuln-dom-xss-spa
description: >
  Gerçek tarayıcıyla (headless Chromium) tetiklenen DOM-tabanlı XSS, JavaScript-yoğun
  SPA'lar ve çok-adımlı oturum akışları. Ham HTTP'nin GÖREMEDİĞİ client-side sink'ler,
  hash/route tabanlı render ve "yanıtta payload yok ama DOM'da çalışıyor" sınıfı burada
  kazanılır. browser_navigate / browser_eval / browser_dom / browser_screenshot araçları.
---

# 🧭 DOM-XSS & SPA — gerçek tarayıcıyla tetikle ve KANITLA

> **Tek cümle:** Ham yanıtta payload görünmüyor diye XSS yok deme. DOM-XSS, sunucu
> yanıtına HİÇ dokunmaz — zararlı veri tarayıcıda, JavaScript bir sink'e yazınca
> çalışır. Onu yakalamak için sayfayı GERÇEKTEN render etmen gerekir.

İlişkili: [[vuln-xss]] [[data-flow-and-mental-model]] [[adversarial-verification]] [[baseline-and-signal]]

## NE ZAMAN tarayıcıya geç (cyp_send_request yetmediğinde)
- Yanıt gövdesi büyük ölçüde JS bundle / boş `<div id="app">` → içerik client-side render (SPA).
- Payload yanıtta encode'lu/yok ama yine de DOM'a `innerHTML`/`location`/`eval` yoluyla akabiliyor.
- Hash-route (`#/...`), `location.hash`, `postMessage`, `localStorage` tabanlı akışlar.
- Çok-adımlı oturum: login → token JS'te tutuluyor → sonraki sayfa onu kullanıyor.

## ARAÇLAR
```
cyp_browser_navigate {url, waitMs?, bodyLimit?}
   → gerçek Chromium'da yükler, JS'i çalıştırır. DÖNER: final url, title, html, dialogs[].
     dialogs[] BOŞ DEĞİLSE (ör. "alert: 1") = bir script ÇALIŞTI → DOM-XSS KANITI.
cyp_browser_eval {expr}
   → yüklü sayfada JS çalıştır (document.cookie, localStorage, innerHTML oku; sink tetikle).
     DÖNER: result + bu sırada açılan dialogs[].
cyp_browser_dom {bodyLimit?}      → JS sonrası gerçek outerHTML (kullanıcının gördüğü DOM).
cyp_browser_screenshot {}          → PNG kanıt (köprü dizinine kaydeder, yol döner).
```
> Tarayıcı SCOPE zorlar — kapsam dışı host'a navigate reddedilir. Maliyet: Chromium ilk
> `browser_*` çağrısında başlar; gerekmiyorsa ham HTTP'de kal (recon/fuzz tarayıcı açmaz).

## DOM-XSS KANIT DÖNGÜSÜ (sink → kaynak → tetik → dialog)
1. **Kaynak (source):** kullanıcı-kontrollü giriş — `location.hash`, `location.search`,
   `document.referrer`, `postMessage`, `localStorage`, URL path segmenti.
2. **Sink:** `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str)`,
   `location=`, `el.src/href`, jQuery `$(...)`, `Function()`. `browser_dom` + `browser_eval`
   ile kaynaktan sink'e veri akışını doğrula (bkz. [[data-flow-and-mental-model]]).
3. **Tetik:** payload'ı KAYNAĞA koy ve sayfayı render et:
   ```
   browser_navigate url="https://hedef/#<img src=x onerror=alert(1)>"
   browser_navigate url="https://hedef/sayfa?q=<svg/onload=alert(1)>"
   ```
   Sonra dönen `dialogs` dizisine bak. `["alert: 1"]` → **tetiklendi, kanıtlandı.**
4. **dialog yoksa ama şüphe varsa:** benzersiz işaret bırak ve DOM'da ara:
   ```
   browser_eval expr="window.__cyp=0; (function(){ /* payload yolu */ })(); window.__cyp"
   browser_eval expr="document.documentElement.innerHTML.includes('CYPMARKER')"
   ```
   Reflekssiz markası DOM'a HTML olarak girdiyse (text-encode DEĞİL) → XSS'e giden akış var.

## SPA / ÇOK-ADIMLI AKIŞ
- `browser_navigate` ile giriş yap, ardından `browser_eval` ile token/oturum durumunu oku:
  `browser_eval expr="localStorage.getItem('token')"` · `expr="document.cookie"`.
- Client-side route'ları gez: `browser_eval expr="location.hash='#/admin'"` → sonra
  `browser_dom` ile yetkisiz görünen panel/aksiyon var mı bak (client-side authz = sahte güvenlik).
- Gizli/JS-üretimli endpoint'leri çıkar: `browser_dom` içindeki `fetch('/api/...')`,
  `axios`, route tablosu → bunları `cyp_send_request` ile DOĞRUDAN dövmeye geç (daha hızlı).

## KANIT DİSİPLİNİ (kritik/high için ZORUNLU — [[adversarial-verification]])
- PoC'a TAM tetik URL'sini/expr'i ve dönen `dialogs` çıktısını koy. "DOM-XSS var" demek YETMEZ.
- `verify_note`: "browser_navigate `#<img onerror=alert(1)>` → dialogs=['alert: 1'], 2x tekrar".
- False-positive ele: yanıt sadece YANSITIYOR ama tarayıcı ÇALIŞTIRMIYORsa (CSP, text-encode,
  framework auto-escape) → bu XSS DEĞİL. `dialogs` boşsa ve DOM'da text-encode görüyorsan DURMA noktası.
- CSP'yi kontrol et: `browser_eval expr="[...document.scripts].length"` + response CSP header;
  CSP `script-src` katıysa pratik exploitability düşebilir → etkiyi dürüstçe ayarla.

## ÖZET
1. Yanıt boş/JS-yoğun ya da payload yansımıyor ama akıyor → tarayıcıya geç.
2. Kaynak→sink akışını `browser_dom`/`browser_eval` ile doğrula.
3. Payload'ı kaynağa koy, `browser_navigate`/`browser_eval` ile tetikle, `dialogs`'la kanıtla.
4. SPA'da client-side route + token durumunu gez; gizli API'leri çıkarıp ham HTTP'ye dön.
5. dialog yoksa XSS yok say (text-encode/CSP) — dürüst kanıt kapısı.

## DOĞRULAMA — GERÇEKTEN ATEŞLE (executed_effect, halüsinasyon önleme)
XSS iddiasını "yansıma gördüm"de bırakma. `cyp_browser_navigate` ile payload'lu URL/fragment'ı yükle; dönen `dialogs` DOLU ise (alert/confirm/prompt çalıştı) bu executed_effect KANITIDIR. Ardından `cyp_browser_screenshot` al, `path`'i `extracted_evidence`'a yaz; `proof_kind=executed_effect`, `status=confirmed`. Ateşleyemiyorsan (sadece encode'lu yansıma) `proof_kind=differential/inferential`, `status=theoretical/probable` — DOĞRULANDI DEME.
