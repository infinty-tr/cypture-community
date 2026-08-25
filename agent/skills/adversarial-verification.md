---
name: adversarial-verification
description: >
  Bir bulguyu RAPORLAMADAN ÖNCE onu ÇÜRÜTMEYE çalış — kıdemli avcı, kendi bulgusuna
  düşman gibi yaklaşır. Varsayılan: "gerçek olduğu KANITLANANA kadar bu YANLIŞTIR."
  Çok-bakışlı çürütme (tekrar-üretilebilirlik, baseline karışıklığı, ortam artefaktı,
  gerçek-etki, kaynak-atfı). Sadece TÜM çürütme denemelerini SAĞ KALAN bulgu rapora girer.
  False-positive'i dipte tutan disiplin — bir aracı "profesyonel"den ayıran tam budur.
---

# 🔪 ADVERSARIAL DOĞRULAMA — kendi bulgunu çürütmeye çalış

> **Tek cümle:** Acemi bulgusunu sevip kaydeder; usta bulgusundan ŞÜPHE eder ve onu
> öldürmeye çalışır. Yalnızca öldürülemeyen bulgu gerçektir. Rapora "muhtemel"i değil,
> **çürütme denemelerinden sağ çıkanı** koy.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[hunter-intuition]]

Bu, tek bir "ikinci istek" değildir — bir bulguyu FARKLI eksenlerden yıkmaya çalışan
sistemli bir red-team öz-denetimidir. Her **critical/high** bulgu (ve şüpheli medium)
RAPORDAN ÖNCE bu beş kapıdan geçmelidir.

---

## 5 ÇÜRÜTME KAPISI (her birinde "bu bulgu YANLIŞ olabilir mi?" diye sor)

### 1. TEKRAR-ÜRETİLEBİLİRLİK — tek seferlik miydi?
- Aynı isteği **2-3 kez** tekrar at. Sapma HER seferinde mi, yoksa bir kez mi çıktı?
- Farklı sıra/zamanlama ile dene. Tek seferlik → **çürütüldü** (jitter/cache/yarış artefaktı).
- Kural: tekrar üretilemeyen sapma BULGU DEĞİLDİR.

### 2. BASELINE KARIŞIKLIĞI — "anomali" aslında normal mi?
- Payload'sız, **temiz** isteğin yanıtıyla kıyasla. Gördüğün davranış payload'a mı bağlı,
  yoksa endpoint zaten öyle mi davranıyor?
- Örn: "500 aldım" → ama geçersiz HER girdide 500 dönüyorsa bu SQLi değil, kötü hata yönetimi.
- Kontrol grubu: zararsız ama yapısal olarak benzer bir girdi de aynı sonucu veriyor mu?

### 3. ORTAM ARTEFAKTI — WAF/cache/proxy/rate-limit mi?
- Yanıt farkı gerçek uygulama davranışı mı, yoksa araya giren katman mı (CDN cache HIT/MISS,
  WAF blok sayfası, rate-limit 429, load-balancer farklı backend)?
- Header'lara bak (Age, X-Cache, Via, Server). Sapmayı bu katmanlar açıklıyorsa → **çürütüldü**.

### 4. KAYNAK ATFI — yansıma gerçekten ENJEKTE mi oldu?
- XSS/SSTI/injection'da: girdin yanıta DÜŞTÜ diye değil, **bağlam içinde YÜRÜDÜ/DEĞERLENDİ** mi?
  `{{7*7}}` → metinde `{{7*7}}` görünüyorsa SSTI YOK; `49` görünüyorsa VAR.
- Reflected içerik encode edilmiş mi (`&lt;` vs `<`)? Encode edilmişse XSS değil.
- "İddia ettiğim zafiyet, gözlemlediğim sapmanın TEK açıklaması mı?" Alternatif açıklama varsa zayıf.

### 5. GERÇEK ETKİ — sömürülebilir mi, yoksa teorik mi?
- "Mümkün" ile "sömürülebilir" farkı: bir saldırganın bundan ne kazanacağını SOMUT göster.
- IDOR → gerçekten BAŞKASININ verisi mi döndü (kendi 2. hesabınla teyit)? Self-data ise düşük.
- Open redirect → gerçekten dış adrese mi gidiyor, yoksa same-origin mi? Etki yoksa severity düşür.

---

## KARAR

```
5 kapının HEPSİNDEN geçti (sağ kaldı)        → verified:true, güven: confirmed. Rapora gir.
Bir kapı çürüttü (artefakt/tek-seferlik/encode) → RAPORA GİRME, ya da info/düşük olarak not düş.
Kısmen sağ kaldı (etki belirsiz ama gerçek)    → verified:false ama "muhtemel", severity DÜŞÜR + verify_note.
```

> `verify_note`'a HANGİ kapılardan nasıl geçtiğini yaz: "2x tekrar üretildi; temiz baseline 200,
> payload 500+SQL hata izi; cache MISS; ikinci kimlikle başkasının kaydı döndü." Bu, rapora güven verir.

## ÇOK-BAKIŞ (mümkünse)
Aynı bulguyu **farklı eksenlerden** teyit et — tek bir kanıt yerine bağımsız iki yol:
SQLi'yi hem hata-tabanlı hem boolean-tabanlı; IDOR'u hem GET hem PATCH ile; SSRF'i hem
yanıt-farkı hem OOB ile. İki bağımsız eksen sağ kalırsa bulgu kurşun-geçirmezdir.

## ÖZET — 3 REFLEKS
1. Varsayılan: bulgu, kanıtlanana kadar YANLIŞTIR. Onu öldürmeye çalış.
2. 5 kapı: tekrar-üretilebilirlik · baseline · ortam-artefaktı · kaynak-atfı · gerçek-etki.
3. Yalnız sağ kalan rapora girer; `verify_note` çürütme denemelerini belgeler.
