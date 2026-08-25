---
name: vuln-xss
description: >
  Cross-Site Scripting (Reflected/Stored/DOM/Blind). Saldırgan girdisinin
  tarayıcı DOM/HTML/JS bağlamında script olarak çalıştığı durumlarda uygulanır.
  Ana karar: yansıma BAĞLAMINI tespit et, encode ediliyor mu, bağlama uygun kaç.
---

# 🩸 CROSS-SITE SCRIPTING (XSS) — girdi tarayıcıda kod olarak çalışıyor

> **Tek cümle:** Girdinin nereye yansıdığını (bağlam) GÖR, encode edilip edilmediğini ölç, sadece o bağlamdan çıkışı kanıtla — körlemesine payload atma.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Sink = TARAYICI: girdi HTML/DOM/JS olarak render ediliyor. Test et eğer: parametre/başlık/path/body değeri sayfada yansıyor, bir input başka kullanıcıya gösteriliyor (stored), ya da client-side JS `document.write`/`innerHTML`/`eval`/`location` gibi sink'lere `location`/`postMessage`/`referrer` source'undan veri akıtıyor.
- Yansıma da sink de yoksa (girdi hiçbir yerde görünmüyor, sadece JSON API datası, Content-Type non-HTML ve sniff kapalı): **SKIP: tarayıcı render sink'i yok.**

## 2. İNSAN MUHAKEMESİ
- Veri girdiden → sunucu/DB → HTML response veya → client JS → DOM sink. Geliştirici çıktıyı **bağlama göre** encode etmeyi kaçırmış olabilir: HTML body'de `<>` kaçmamış, attribute içinde `"` kapanıyor, `<script>` bloğunda `</script>` ya da `'` kırılıyor, JS template literal'de `${}`/backtick açık.
- Tipler: **Reflected** (aynı yanıt), **Stored** (kaydedilip başka sayfa/kullanıcıda çıkar — [[data-flow-and-mental-model]] §3 "sonuç nerede çıkıyor"), **DOM** (sunucu temiz, kırılma client JS'te), **Blind** (yansıma görünmez, admin paneli gibi yerde çalışır → OOB).

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- Baseline: parametreye **zararsız benzersiz işaretçi** gönder: `xss123`. Yanıtta/DOM'da nerede ve NASIL çıktığını bul (HTML body mi, `value="..."` attribute mi, `<script>var x='...'` mi, `href`/URL mi).
- Bağlamı gördükten sonra TEK bağlam-kırıcı karakter probu: HTML body için `xss123<i>`, attribute için `xss123">`, JS string için `xss123';`. Gözlem: işaretçi **encode EDİLMEDEN** mi (`<` ham mı yoksa `&lt;` mi) çıktı.
- DOM XSS: response'ta yoksa client JS'i oku — source (`location.hash`, `location.search`, `document.referrer`, `postMessage`) → sink (`innerHTML`, `document.write`, `eval`, `setAttribute('href',…)`) zincirini izle.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** işaretçi, bulunduğu bağlamda **anlamlı karakterleri encode edilmeden** yansıdı (HTML body'de ham `<`, attribute'ta ham `"`, script bloğunda ham `'`/`</`). Ya da DOM'da source→tehlikeli sink kanıtlandı.
- **Gürültü değil aday DEĞİL:** `&lt;`/`&quot;`/`\x3c` olarak encode edilmiş yansıma; sadece 200 dönmesi; WAF blok sayfası; girdinin JSON body'de string olarak text gösterilmesi.

## 5. DOĞRULAMA KAPISI (kanıt)
- Bağlama uygun **minimal kanonik** payload ile çalışmayı göster ve baseline farkını kaydet:
  - HTML body: `<img src=x onerror=alert(document.domain)>`
  - Attribute (kapan): `"><svg onload=alert(document.domain)>`
  - JS string: `';alert(document.domain)//`
- Kanıt = baseline (işaretçi text) vs payload (DOM'da execution/parse) farkı + N≥2 tekrar + negatif kontrol (encode edilen benzer paramda çalışmaz). Her isteğin request_id'sini sakla. Stored'da: yazma isteği + okuma/görüntüleme isteğini AYRI request_id ile bağla.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Bağlam ekseni:** doğru kapatma seç (`</script>`, `">`, `'`, backtick/`${}`).
- **Encoding ekseni:** URL/double-URL, HTML-entity, `String.fromCharCode`, JS unicode `\u`.
- **Tag/event ekseni:** `<script>` bloklanırsa `<img onerror>`, `<svg onload>`, `<details ontoggle>`.
- **Sink ekseni (DOM):** `srcdoc`, `javascript:` URI, `data:` URI.
- **Blind ekseni:** yansıma yoksa OOB callback (Burp/Cypture collaborator benzeri `<script src=//OOB/>`) — geri dönüş = kanıt.
- Her eksen bir hipotez; 3-5 denemede sinyal yoksa **dürüstçe kapat.**

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Encode edilmiş yansımayı XSS sanmak:** `&lt;img&gt;` çalışmaz — ham çıkışı doğrula.
- **Self-XSS raporlamak:** kullanıcının kendi konsoluna/sadece kendine gösterilen alana yapıştırdığı payload — başka kullanıcıya ulaşmıyorsa geçersiz.
- **WAF sayfasını yanlış okumak:** payload yansımış gibi görünen blok sayfası ≠ execution.
- **Reflection≠execution:** girdi yansıdı ama `<>` kaçmış / CSP `script-src` engelliyor — alert tetiklenmiyorsa kanıt yok.
- **CSP'yi atlamak:** sıkı CSP varsa inline script çalışmaz; bunu hesaba kat.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** bağlama uygun payload DOM'da execute oldu (alert/OOB) + N tekrar + negatif kontrol tutarlı.
- **Sinyal yok, kapat:** tüm bağlamlarda yansıma encode ediliyor veya hiç sink yok; DOM'da source→sink zinciri kırık.
- **Şüpheli, ilerle:** ham yansıma var ama CSP/filtre execution'ı kesiyor → bypass eksenlerini dene, sonra karar ver.

## ÖZET — 5 KURAL
1. Önce işaretçiyle (`xss123`) **bağlamı gör**, sonra payload seç.
2. Encode edilmemiş ham çıkış = sinyal; encode = gürültü.
3. Bağlama göre kaç: body/attribute/script/JS-template ayrı kapanış.
4. Reflection değil **execution** kanıtla (alert/OOB) + negatif kontrol.
5. Self-XSS ve WAF sayfasını rapor etme; stored'da çıkış noktasını bağla.

## DOĞRULAMA — GERÇEKTEN ATEŞLE (executed_effect, halüsinasyon önleme)
XSS iddiasını "yansıma gördüm"de bırakma. `cyp_browser_navigate` ile payload'lu URL/fragment'ı yükle; dönen `dialogs` DOLU ise (alert/confirm/prompt çalıştı) bu executed_effect KANITIDIR. Ardından `cyp_browser_screenshot` al, `path`'i `extracted_evidence`'a yaz; `proof_kind=executed_effect`, `status=confirmed`. Ateşleyemiyorsan (sadece encode'lu yansıma) `proof_kind=differential/inferential`, `status=theoretical/probable` — DOĞRULANDI DEME.
