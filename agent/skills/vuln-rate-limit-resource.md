---
name: vuln-rate-limit-resource
description: >
  Rate Limit & Kaynak Tüketimi sınıfı (OWASP API4): kritik bir endpoint (login,
  OTP, reset, search) ya da ağır bir işlem varsa uygulanır. Rate-limit'in var
  olup olmadığını, bypass edilebilirliğini (header rotation, path/case varyasyonu)
  ve kaynak tüketimi yüzeyini bulur. Ana karar: limit GERÇEKTEN yok/atlandı VE
  somut bir etki (OTP brute mümkün) var mı — yoksa servisi yormadan kanıtla.
---

# 🚦 RATE LIMIT & KAYNAK TÜKETİMİ (API4) — kritik uçta limit yok/atlanıyor VE somut etki varsa açıktır

> **Tek cümle:** Kritik bir endpoint'i kontrollü tekrarla yokla; kanıt "çok istek attım" değil, limitin YOKLUĞU/ATLANIŞI + somut etkidir (OTP brute mümkün, ağır sorgu kabul edildi) — ASLA servisi yormadan.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[business-logic-reasoning]] [[chain-attack-builder]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Brute/abuse'a değer bir uç ya da ağır bir işlem varsa: login, OTP/2FA doğrulama, parola sıfırlama, kupon/davet/referral kodu, e-posta/SMS gönderimi, search, export/report, GraphQL alias-batching/pagination, dosya/render işlemleri.
- İpuçları: kısa sayısal OTP (4-6 hane), tahmin edilebilir/ardışık kod, limitsiz `limit=`/`page_size=`/`per_page=`, derin nesting kabul eden filtre, büyük gövde alan uç, regex/arama alanı (ReDoS yüzeyi), GraphQL `__schema`/iç içe sorgu derinliği.
- **Distributed brute farkı:** limit tek hesaba/kullanıcıya bağlıysa, tek parola ile ÇOK hesabı (password spraying) ya da tek hesaba çok IP'yi denemek limit modelinin kör noktasıdır — sayacın hangi eksene (IP / kullanıcı / oturum / global) bağlı olduğunu önce belirle.
- SKIP: kritik olmayan/idempotent okuma uçları; iş mantığı suistimali baskınsa → [[business-logic-reasoning]]; saf hacim-DoS (volumetric) istenmiyorsa o yola ASLA girme.

## 2. İNSAN MUHAKEMESİ
- Geliştirici rate-limit'i ya hiç koymamış, ya UI üzerinden varsayıp API'de unutmuş, ya da tek bir eksene (IP/header/email) bağlamış olabilir — diğer eksen serbest kalır. [[request-economy]]: az ve hedefli istekle limitin varlığını ve EKSENİNİ ölç, brute'u GERÇEKTEN çalıştırma.
- Kaçırılan yer: limiti yalnız IP'ye bağlamak (X-Forwarded-For ile atlanır); path/case normalizasyonu öncesi limit; OTP doğrulama sayacının yeni kod istenince sıfırlanması; OTP'yi yenileyip pencereyi resetleyerek sınırsız deneme; pahalı işlemi anonim erişime açmak; sayacı email'e bağlayıp username/telefon varyantıyla aynı hesabı vurmak.
- Mantık: "Korumanın hangi anahtara bağlı olduğu" sorusu sömürünün anahtarıdır. Anahtarı değiştirebiliyorsan (header/oturum/hedef-kimlik), limit pratikte yoktur.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Tek geçerli istek; status, dönen header'lar (`X-RateLimit-Limit/Remaining/Reset`, `Retry-After`, `RateLimit-*`), süre/gövde boyutunu not et. request_id sakla. Header'lar zaten limit politikasını sızdırabilir — önce oku, deneme harcamadan eşiği öğren.
- **Etki uygunluğu:** uç brute'a değer mi? (4-6 haneli OTP / ardışık kod = evet; 128-bit random token = hayır). Değmiyorsa SKIP, gürültü üretme.
- **Kademeli prob (kontrollü, KÜÇÜK N):**
  1. **Limit var mı + hangi eksende:** Aynı kritik isteği KÜÇÜK kontrollü bir N (örn. 10-15) tekrarla → 429/kilit/`Retry-After` geldi mi, yoksa hepsi 200 mü? Eşik geldiyse `Remaining` sayacının düştüğünü gözle (eksen = bu kimliğe bağlı). Hesap kilitlemeyecek değerde, tercihen test/own hesabı.
  2. **Eksen bypass'ı:** Limit varsa TEK varyasyonla yokla — her istekte farklı `X-Forwarded-For` (header eksen), yeni oturum/token (oturum eksen), farklı hedef-email/username (kullanıcı eksen), path/case varyasyonu (`/Login`, `/login/`, `//login`, `%2flogin`) → sayaç sıfırlanıyor mu?
  3. **Race on limit:** Sayaç atomik değilse, `Remaining=1` anında eşzamanlı küçük burst (3-5 istek) sayacın altına sızabilir; `cyp_race_window_send` ile DAR pencerede sığ bir burst dene (servisi yormadan), birden fazla 200 geçti mi.
  4. **Kaynak/expensive-endpoint:** Ağır uçta tek "büyük" prob (makul büyük payload / derin JSON-GraphQL nesting / `limit=99999` / pahalı regex) → kabul edilip orantısız işliyor mu? (Tek atış, baseline süresine karşı ölç.)
- **Cypture notu:** Küçük N'yi `cyp_send_request`'i kontrollü tekrarlayarak ölç; her istekte status + `Retry-After`/`Remaining` topla. `cyp_compare_requests` ile baseline↔eşik farkını netleştir. Bypass testinde SADECE tek ekseni değiştir, gerisini sabit tut. [[request-economy]] sınırı: N minimumda, `cyp_run_intruder`/otomatik brute ASLA başlatma.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Kritik uçta küçük N boyunca 429/kilit YOK (limit yok) + uç brute'a değer; VEYA header/path/oturum/kullanıcı eksenlerinden biri sayacı sıfırladı (eksen bypass); VEYA `Remaining=1` anında race burst birden fazla 200 geçirdi (atomik değil); VEYA tek büyük/derin istek orantısız kaynak (uzun süre/büyük cevap) tüketti.
- **Gürültü (aday DEĞİL):** Tek seferlik yavaşlık; 200 ama uç brute'a değmez (uzun random token); 429 GELDİ ve varyasyon onu sıfırlamadı (koruma çalışıyor); WAF/CDN bloğu; jenerik hata; `Remaining` düşüp eşikte düzgün 429 (sayaç sağlam).

## 5. DOĞRULAMA KAPISI (kanıt)
- **Limit yokluğu:** Kontrollü N istek boyunca limit/kilit YOK; aynı koşulda korumalı bir uç 429 verirken bu vermiyor (karşılaştırma). request_id dizisi + `Remaining` header'ının düşmediği gözlemi.
- **Eksen bypass:** Limitsiz koşulda 429 alıp, SADECE tek eksen (header/path/oturum/hedef) ekleyince N istek daha geçiyor → sayaç sıfırlandı; "öncesi 429" + "sonrası 200" request_id'leri yan yana.
- **Race:** Aynı `Remaining=1` penceresinde gönderilen burst'te beklenenden fazla 200; request_id'ler + zaman damgaları.
- **Somut etki (argümanla, brute YAPMADAN):** OTP/kod uzayını + limit yokluğunu birleştirip brute'un MÜMKÜN olduğunu göster (örn. 4 haneli OTP, limit yok, ortalama ~22ms cevap → 10⁴ deneme erişilebilir/dakikalar). Distributed için: tek parola N hesaba serbest denenebiliyor. Kaynak için: tek probun baseline'a göre ölçülen aşırı süre/cevap boyutu (örn. baseline 40ms ↔ derin sorgu 8s).
- N tekrar; her kanıt = baseline request_id + tetikleyici request_id(ler) + negatif karşılaştırma.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Header rotation ekseni:** `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `Forwarded: for=`, `X-Originating-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Via` — her istekte farklı/rastgele IP; sayaç IP'ye bağlıysa sıfırlanır. Tek header değil, çoklu kombinasyon da dene (proxy hangisine güveniyor belirsizse).
- **Path/method ekseni:** case (`/LOGIN`), trailing slash, encoded (`%2f`, `%2e`), çift slash, `;` matrix-param, parametre sırası, GET↔POST, HTTP/1.1↔HTTP/2 — normalizasyon öncesi limit'i atlatır.
- **Kimlik/oturum/hedef ekseni:** sayacın IP mi kullanıcı mı oturum mu üstünde olduğunu test et; yeni anon oturum/token ile sayacı sıfırla; OTP doğrulamada hedef-email/telefon sabit, kod-tahmini serbest mi; distributed: hedef-kimliği döndürerek tek parolayı yay (password spraying — limit per-account ise tetiklenmez).
- **Zamanlama/race ekseni:** pencere sıfırlanmasını gözle (`Reset` header); OTP yeniden gönderiminin sayacı resetleyip resetlemediği; `cyp_race_window_send` ile `Remaining=1` anında sığ burst (TOCTOU). Servisi yormadan.
- **Kaynak ekseni:** büyük payload, derin JSON/GraphQL nesting (`__schema` introspection + alias batching), limitsiz pagination/export, pahalı regex/arama (ReDoS girişi), pahalı render/PDF — TEK atış, hafif, baseline'a karşı ölç. Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Limit'i test ederken hesap kilitlemek/servisi yormak:** EN BÜYÜK tuzak. [[request-economy]] — küçük kontrollü N ile VARLIĞI ölç; brute/DoS YAPMA. Kendi/test hesabı kullan; OTP yanlış denemeleri hesabı kilitleyebilir.
- **Limitsizliği etkisiz uçta açık sanmak:** uzun random token/UUID brute edilemez; "limit yok" tek başına bulgu değil, somut brute/abuse etkisi şart.
- **Tek yavaşlığı kaynak tüketimi sanmak:** baseline'a karşı ölçüm + tekrar olmadan iddia yok; soğuk-cache/JIT ilk istek hep yavaş olabilir.
- **429'u atlandı sanmak:** 429 gördükten sonra varyasyonun GERÇEKTEN yeni 200'ler ürettiğini doğrulamadan "bypass" deme.
- **DoS'u kanıtlamak için saldırmak:** varlığı (limit yokluğu/orantısız maliyet) argümanla kanıtla, volumetric saldırı YAPMA — kapsam dışı ve zararlı.
- **Client-side limit'i gerçek koruma sanmak:** UI butonunu kilitleyen JS, API'de limit OLDUĞU anlamına gelmez; doğrudan API'yi yokla.
- **WAF/CDN 429'unu uygulama limiti sanmak:** kaynak (Cloudflare vb.) cevabı uygulamanın kendi limitini göstermez; bypass'ta hangi katmanın reddettiğini (`Server`/`Via`/`CF-Ray`) ayırt et.
- **Soft-block'u limit yok sanmak:** 200 dönüp arkada "shadow ban"/silent-drop yapan koruma; cevap içeriği gerçekten işlendi mi doğrula.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** kritik uçta limit yok/atlandı (request_id dizisi) + somut etki (brute mümkün argümanı / ölçülü orantısız kaynak / atomik-olmayan race) + negatif karşılaştırma.
- **Sinyal yok, kapat:** küçük N'de 429/kilit geldi, header/path/oturum/hedef/race varyasyonları sayacı sıfırlamadı; koruma çalışıyor.
- **Şüpheli, ilerle:** limit zayıf görünüyor ama etki belirsiz → tek hedefli bir bypass/ölçüm probu daha (servisi yormadan), sonra karar; istek bütçesini boşa harcama.

## ÖZET — 5 KURAL
1. [[request-economy]]: limiti KÜÇÜK kontrollü N ile yokla; ASLA brute/DoS yapma, hesap kilitleme.
2. "Limit yok" tek başına bulgu değil; somut etki (kısa OTP/kod brute mümkün, distributed sprey) şart.
3. Önce limitin EKSENİNİ bul (IP/kullanıcı/oturum/global); bypass = o ekseni tek tek değiştirip "429 → 200" dizisi göstermek.
4. Kaynak tüketimini baseline'a karşı ölçülen orantısız maliyetle, tek hafif atışla göster.
5. Her kanıt = baseline request_id + tetikleyici request_id(ler) + negatif karşılaştırma.
