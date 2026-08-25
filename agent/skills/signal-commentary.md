---
name: signal-commentary
description: >
  Operatör için CANLI yorum/sinyal akışı üretme sözleşmesi. Uzman/orkestratör,
  ilginç gözlemleri kısa, kanıt-temelli, etiketli satırlar olarak yazar; UI bunları
  ayrı "Sinyal / Yorum" şeridinde gösterir. Abartı/halüsinasyon YOK — sadece gerçek iz.
---

# 💡 SİNYAL / YORUM AKIŞI — operatöre canlı, insani anlatım

> **Amaç:** Operatör akışı izlerken "şu an ilginç ne oluyor?"u tek bakışta görsün. Ham
> log'a ek olarak, **karar anlarında** kısa yorum bırak. Bu satırlar UI'da ayrı bir
> şeride akar; bu yüzden **etiketli** ve **tek satır** olmalılar.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[core-contract]] [[chain-attack-builder]]

## NE ZAMAN YAZILIR (tetikleyiciler)
- Bir dalga/faza geçerken (kısa "ne yapacağım" niyeti).
- **Güçlü sinyal** bulunca (baseline'dan ölçülebilir sapma; ör. tek tırnak → 500+SQL izi).
- **Anomali / beklenmedik** durum (yetkisiz 200, açık dizin, sızan token, tuhaf header).
- **Zincir fikri** doğunca (iki bulgu birleşince daha büyük etki).
- Bir yolu **kapatırken** (neden çıkmaz: "TE normalize ediliyordu, raw_socket ile aşıldı").

## NASIL YAZILIR (biçim — ZORUNLU)
Satır başında tam olarak şu etiketlerden biriyle, TEK satır, Türkçe:
- `💡 SİNYAL: <kısa gözlem + neden önemli>`  — umut verici iz / aday.
- `⚠ DİKKAT: <anomali / risk / beklenmedik>`  — dikkat çekici, doğrulanmalı.
- `🔗 ZİNCİR: <bulgu A + bulgu B → daha büyük etki>`  — zincirleme fikri.

Örnekler:
- `💡 SİNYAL: /login email alanı tek tırnakta 500 + "SQL syntax" izi — SQLi güçlü aday, kademeli doğruluyorum.`
- `⚠ DİKKAT: /api/admin/users oturumsuz 200 dönüyor — yetkisiz erişim olabilir, iki-kimlikle teyit edeceğim.`
- `🔗 ZİNCİR: /upload'da SVG kabul + /profile'da yansıma → stored XSS → oturum çalma denenebilir.`

## KURALLAR (anti-halüsinasyon)
1. **Yalnız GÖRDÜĞÜN şey.** Yorum da kanıta dayanır; "olabilir" tahminini `⚠ DİKKAT` ile işaretle, kesin dil kullanma.
2. **Kısa.** Tek satır, ~1-2 cümle. Uzun analizi tile/log'a bırak; buraya özünü yaz.
3. **Spam yok.** Her HTTP isteği için değil; yalnız karar anlarında. Aynı sinyali tekrar yazma.
4. **Abartma.** "Kritik RCE buldum!" deme — doğrulanınca `cyp_create_finding` zaten yazar. Burada SÜREÇ yorumu var, ilan değil.
5. Bu satırlar log'a da gider (zararı yok); UI etikete göre süzer.


## CANLI YORUM — KANIT-ETİKETLİ, ABARTISIZ
Her `💡 SİNYAL` / `⚠ DİKKAT` / `🔗 ZİNCİR` satırı bir request_id'ye ya da ölçülen somut sapmaya dayanmalı; dayanmıyorsa YAZMA.
- ✅ İYİ: `💡 SİNYAL: /search.php?q=' → 500 + SQL hata izi (req_42); version() denenecek.`
- ❌ KÖTÜ: `💡 SİNYAL: Burada XSS ile session hijack mümkün!` (kanıtsız büyütme)
Kanıt seviyesini etiketle (KANIT/GÖZLEM/HİPOTEZ). Doğrulanmamışı "olası/teorik" diye işaretle; "kritik/doğrulandı" deme. Abartma, kısa tut, Türkçe yaz.
