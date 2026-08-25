---
name: vuln-cors-misconfig
description: >
  CORS Misconfiguration. Sunucu keyfi/saldırgan kontrollü Origin'i yansıtıp
  credentials'a izin verdiğinde uygulanır. origin reflection, null origin,
  suffix/prefix/regex bypass, credentials:true + hassas veri exfil. Ana karar:
  ACAO yansıması + Allow-Credentials:true birlikte mi ve arkada kimliğe-bağlı veri var mı.
---

# 🌐 CORS MISCONFIGURATION — sunucu yabancı origin'e güveniyor

> **Tek cümle:** `Access-Control-Allow-Origin`'in saldırgan origin'ini YANSITIP `Allow-Credentials: true` dediği ve arkasında kimliğe bağlı hassas veri olduğu yer kanıttır — yalnız `*` korku değildir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[chain-attack-builder]] [[vuln-xss]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Test et eğer: endpoint cookie/Authorization ile **kimliğe bağlı hassas veri** dönüyor (profil, token, hesap, API key, CSRF token, mesaj), VE yanıtta CORS başlıkları (`Access-Control-Allow-Origin`) görülüyor ya da `Origin` ekleyince görülebilir.
- Endpoint auth gerektirmeyen tamamen public veri dönüyorsa, ya da hiç CORS başlığı yoksa ve credentialed cross-origin okuma mümkün değilse: **SKIP: okunacak hassas/kimliğe-bağlı veri yok.**

## 2. İNSAN MUHAKEMESİ
- Tarayıcı same-origin policy ile cross-origin okumayı engeller; CORS bunu **kasıtlı** gevşetir. Geliştirici "izin verilen origin"i dinamik olarak gelen `Origin`'i **yansıtarak** uygulamış olabilir (whitelist yerine echo), ya da `null`'a güvenmiştir, ya da bozuk bir suffix/prefix/regex eşleşmesi kullanmıştır (`endsWith("target.com")`, `startsWith`, kaçışsız `.` regex). Yansıtma + credentials = saldırgan sayfası, kurbanın cookie'siyle yanıtı okur ve exfil eder.
- Soru: "Sunucu hangi Origin'lere `ACAC: true` ile yanıt okutuyor, ve bu kümeyi saldırgan kontrol edebiliyor mu?"

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** isteği **Origin başlığı olmadan** (veya gerçek origin'le) gönder, yanıttaki CORS başlıklarını ve dönen hassas veriyi not et, request_id sakla.
- **Kademeli prob (her biri TEK varyasyon, `cyp_send_request`):**
  1. **Tam yansıma:** `Origin: https://<hedef-evil>` → yanıtta `ACAO: https://<hedef-evil>` (tam yansıma) VE `Access-Control-Allow-Credentials: true` var mı.
  2. **null:** `Origin: null` (sandboxed iframe/`data:` kaynaklı) → yansıyıp credentials true mu.
  3. **suffix:** `Origin: https://<hedef>.<hedef-evil>` (regex/`endsWith` zaafı).
  4. **prefix/substring:** `Origin: https://<hedef-evil>` içinde hedef domain'i barındır (`https://<hedef>evil.com`, `https://evil-<hedef>`).
  5. **subdomain:** `Origin: https://<saldirgan>.<hedef>` (trusted-subdomain → XSS zinciri).
  6. **protokol/port:** `http://` vs `https://`, farklı port kabul mü.
- **Cypture notu:** her prob'da SADECE Origin'i değiştir, gerisi sabit; `cyp_compare_requests` ile baseline↔prob ACAO farkını netleştir. Birden çok rastgele origin'le tekrar et ki "yansıma" mı yoksa "sabit whitelist" mi ayırt edesin.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** ACAO yanıtta **saldırgan origin'ini tam yansıtıyor** + `ACAC: true` + endpoint kimliğe bağlı veri dönüyor. Ya da `Origin: null` yansıyıp credentials true. Ya da suffix/prefix/subdomain varyantı saldırganın kontrol edebileceği bir origin'i kabul ediyor.
- **Aday DEĞİL:** `ACAO: *` (tarayıcı `*` ile credential göndermez — veri public değilse okunamaz, kritik değil); ACAO hiç yok; ACAO sabit bir whitelist origin döndürüyor (farklı Origin'lerde değişmiyor = yansıma yok); sadece OPTIONS preflight 200; `ACAC` yok (credentials okunamaz, sadece anonim cross-origin).

## 5. DOĞRULAMA KAPISI (kanıt)
- Kanıt zinciri: (a) `Origin: <hedef-evil>` → yanıtta `ACAO: <hedef-evil>` + `ACAC: true` yansıması, (b) aynı endpoint kimlik bilgisiyle gerçek hassas veri dönüyor, (c) negatif kontrol: tamamen farklı rastgele bir origin'le tekrar (yansıma tutarlı = echo, sabit kalıyor = whitelist) ve Origin'siz baseline farkı. N≥2 tekrar, her request_id kayıtlı.
- **PoC (exfil):** saldırgan sayfasının `fetch(url,{credentials:'include'}).then(r=>r.text())` ile kurban verisini okuyup OOB'a sızdırabileceğini başlık kanıtıyla göster — başlık (`ACAO: evil` + `ACAC: true`) + hassas-veri ikilisi yeterli; gerçek exfil opsiyonel ama somut PoC değeri yüksek.
- **Subdomain/XSS zinciri:** `*.<hedef>` güveniliyorsa bir subdomain XSS'i ile origin'i ele geçirip veriyi oku → [[vuln-xss]].

## 6. VARYASYON / BYPASS (bloklanınca)
- **null origin:** `Origin: null` (sandboxed iframe `sandbox="allow-scripts"`, `data:`/`blob:` kaynaklı) yansıyor mu — sık atlanan ama exploitable durum.
- **suffix/prefix/substring eşleşme:** `<hedef>.<hedef-evil>` (endsWith zaafı), `<hedef-evil>` içinde hedef substring (`https://<hedef>.evil.com`, `https://not<hedef>`), kaçışsız regex `.` (`https://target-com.evil.com`).
- **alt-domain XSS zinciri:** `*.<hedef>` veya tek bir subdomain güveniliyorsa o subdomain'de XSS/takeover bul, origin'i ele geçir → [[vuln-xss]].
- **protokol/port/case:** `http://` downgrade, port farkı, origin case-insensitive kabul.
- **preflight farkı:** karmaşık istekte (custom header/method) preflight'ı geçirip asıl yanıtın `ACAC` döndüğünü doğrula.
- Her biri hipotez; yansıma/saldırgan-kontrollü origin kabulü yoksa **kapat.**

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **`ACAO: *` + credentials YOK** durumunu kritik sanmak: tarayıcı `*` ile credential göndermez; public veri zaten herkese açık → düşük/geçersiz.
- **Yansıma sandığın aslında whitelist:** sunucu her zaman aynı sabit origin'i dönüyordur; farklı/rastgele `Origin`'lerle test etmeden "yansıyor" deme.
- **`ACAC` olmadan yansımayı kritik sanmak:** credentials okunamıyorsa sadece anonim/cross-origin, kimliğe-bağlı veri exfil edilmez.
- **`Vary: Origin` olmadan cache** karışıklığını gerçek yansıma sanmak (CDN farklı origin'e cache'lenmiş yanıt dönmüş olabilir).
- **Preflight (OPTIONS) 200**'ü exploit kanıtı sanmak: asıl GET'in veri + `ACAC` döndürmesi gerekir.
- **Hassas veri yokken** yansıma+credentials görüp kritik raporlamak — okunacak değer yoksa impact düşük.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** saldırgan-kontrollü origin yansıdı/kabul edildi + `ACAC: true` + endpoint hassas kimliğe-bağlı veri dönüyor, N tekrar tutarlı + negatif kontrol (rastgele origin ile echo doğrulandı).
- **Sinyal yok, kapat:** ACAO yansımıyor (sabit/yok) veya `*` ama credentials yok ve veri public; tüm bypass varyantları reddediliyor.
- **Şüpheli, ilerle:** yansıma var ama veri hassas değil → başka endpoint'lerde aynı zafiyeti ara; ya da null/suffix/subdomain bypass eksenlerine devam; subdomain güveniliyorsa XSS zinciri kur.

## ÖZET — 5 KURAL
1. Önce baseline CORS başlıkları, sonra `Origin: https://<hedef-evil>` TEK prob.
2. Sinyal = origin **yansıması/kabulü** + `Allow-Credentials: true` + hassas veri (üçü birlikte).
3. `*` tek başına ve credentials yokken kritik DEĞİL.
4. Yansımayı whitelist'ten ayır: birden çok rastgele origin'le doğrula + negatif kontrol.
5. null / suffix / prefix / subdomain(+XSS) bypass'larını sırayla dene, yoksa kapat.
