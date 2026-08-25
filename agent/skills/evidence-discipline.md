---
name: evidence-discipline
description: >
  Halüsinasyon önleme ve kanıt disiplini. Her iddia gerçek, loglanmış bir isteğe (request_id)
  ve gözlemlenmiş somut bir farka dayanmak ZORUNDA. Güven seviyeleri, yasak davranışlar ve
  "gözlemlemediğini iddia etme" kuralı. Tüm ajanlar bunu uygular — özellikle zayıf modelde kritik.
---

# 🧪 KANIT DİSİPLİNİ — HALÜSİNASYONA KARŞI

> **Tek cümle:** Gözlemlemediğin hiçbir şeyi iddia etme. Her cümlenin arkasında ya gerçek bir
> `request_id` + gözlemlenmiş fark vardır, ya da o cümle "hipotez" olarak etiketlenir.

Zayıf model en çok şu hatayı yapar: bir istek atar, yanıtı tam okumaz, ama "SQLi buldum" der.
Ya da hiç istek atmadan "muhtemelen savunmasız" der. Bu modül bunu YASAKLAR.

---

## 1. GÜVEN SEVİYELERİ — her cümleyi etiketle

| Seviye | Anlamı | Rapora girer mi? |
|---|---|---|
| **KANIT** | Loglanmış istek(ler) + gözlemlenmiş somut fark + N kez tekrar | ✅ Evet |
| **GÖZLEM** | Gerçek bir yanıtta görülen ham olgu (henüz yorumlanmamış) | Ara not |
| **HİPOTEZ** | "Şu olabilir" — henüz test edilmedi | ❌ Hayır (test et) |
| **TAHMİN** | Gözleme dayanmayan varsayım | ❌ Yasak — sil |

**Kural:** Bir şeyi "buldum / savunmasız / çalışıyor" diye yazmadan önce seviyesi KANIT olmalı.
Değilse "hipotez" yaz ve test et. TAHMİN seviyesindeki cümleyi yazma bile.

---

## 2. ÜÇ SORU KAPISI — bulgu iddia etmeden önce

Bir zafiyet iddia etmeden ÖNCE üçüne de "evet + kanıt" diyemiyorsan, bulgu YOKTUR:

```
1. GERÇEKTEN İSTEK ATTIM MI?
   → request_id var mı? Yanıtın statusCode/body'sini GERÇEKTEN gördüm mü?
   → Hayır ise: bulgu yok. Önce isteği at ve yanıtı oku.

2. BASELINE'DAN ÖLÇÜLEBİLİR BİR FARK GÖRDÜM MÜ?
   → Normal yanıt neydi? Payload'lı yanıt neydi? Fark NE? (kod/süre/boyut/içerik)
   → "Sadece 200 döndü" fark DEĞİLDİR. (bkz. [[baseline-and-signal]])

3. BU FARKI TEKRAR ÜRETEBİLDİM Mİ?
   → Aynı isteği 2-3 kez attığımda aynı sonucu aldım mı? Tek seferlik gürültü olabilir.
   → Tekrarlanmıyorsa: "şüpheli" olarak işaretle, bulgu deme.
```

Üçü de evet + request_id varsa → KANIT. Cypture'ya finding işle.

---

## 3. YASAK DAVRANIŞLAR (zayıf modelin tuzakları)

- ❌ İstek atmadan / yanıtı okumadan sonuç yazmak.
- ❌ Yanıt içeriğini hatırından / varsayımdan UYDURMAK. Görmediğin body'yi alıntılama.
- ❌ "Payload muhtemelen çalıştı" demek. Çalıştıysa KANITINI göster, yoksa "çalışmadı" de.
- ❌ Sadece `200 OK` görüp "zafiyet var" demek. 200 normaldir; fark gerekir.
- ❌ Hata mesajı olmadan "SQLi var" demek. Belirti (DB hatası / time delay / boolean fark) şart.
- ❌ Bir reflection görüp DOM/encoding bağlamını kontrol etmeden "XSS" demek.
- ❌ WAF blok sayfasını / 403'ü zafiyet sanmak.
- ❌ Aynı bulguyu farklı isimlerle çoğaltmak (dedup et).

---

## 4. "BİLMİYORSAN BİLMİYORUM DE"

Gözlemlemediğin bir şeyi doldurma. Boş alanı uydurmaktansa şunu yaz:

```
Tech stack: BİLİNMİYOR (header/hata mesajı gözlemlenmedi)
Auth: BİLİNMİYOR (login akışı henüz izlenmedi)
```

Yanlış bir "MySQL" tahmini, "bilinmiyor"dan **daha kötüdür** — çünkü sonraki ajan ona göre
yanlış yöne saldırır ve token harcar. Belirsizliği dürüstçe işaretle, sonra gözlemle.

---

## 5. KANIT KAYDI FORMATI (bulgu için zorunlu iskelet)

Her bulgu `firstphase.md`'ye bu iskeletle girer — her satır gerçek gözleme dayanmalı:

```
İddia       : [zafiyet türü ve yeri]
Baseline    : req_AAAA → [kod, ms, boyut, ilgili içerik]
Tetikleyici : req_BBBB → [payload] → [kod, ms, boyut, FARK]
Fark        : [tam olarak ne değişti — somut]
Tekrar      : [kaç kez tekrarlandı, sonuç tutarlı mı]
Bağlam      : [reflection bağlamı / hata mesajı / metadata yanıtı — ham alıntı]
Güven       : KANIT
```

Bir alanı dolduramıyorsan o bulgu KANIT değildir → "şüpheli"ye taşı, rapora koyma.

---

## 6. ŞÜPHELİ ≠ BULGU

Belirti var ama doğrulanamadıysa `firstphase.md` → "ŞÜPHELİ / DEVAM" bölümüne yaz
(ne görüldü, ne denenmeli). Bunu BULGU/rapor olarak sunma. Şüpheliyi rapora taşımak
= false positive = sistemin itibarını ve kullanıcının token'ını yakar.

---

## ÖZET — 5 KURAL

1. Her cümleyi etiketle: KANIT / GÖZLEM / HİPOTEZ. TAHMİN'i yazma.
2. Üç soru kapısı geçilmeden bulgu yok (istek attım mı / fark gördüm mü / tekrarlandı mı).
3. Görmediğin yanıtı uydurma. 200 ≠ zafiyet.
4. Bilmiyorsan "BİLİNMİYOR" yaz, tahmin etme.
5. Şüpheli bulguyu rapora değil "ŞÜPHELİ"ye yaz.


## KANIT SINIFI (proof_kind) — DOĞRULANDI vs OLASI vs TEORİK
Her bulguya `proof_kind` + buna bağlı `status` yaz; UI/rapor rozeti buna bağlıdır:

| proof_kind | ne demek | status | UI rozeti | severity tavanı |
|---|---|---|---|---|
| extracted_data | GERÇEK hassas veri çıkardın (DB versiyon/satır, başkasının verisi, /etc/passwd içeriği) | confirmed | DOĞRULANDI | CRITICAL'e kadar |
| executed_effect | GERÇEK çalışan etki gözledin (çalışan XSS+screenshot, SSRF OOB hit, RCE çıktısı, yüklenip çalışan dosya) | confirmed | DOĞRULANDI | CRITICAL'e kadar |
| differential | ölçülen baseline-sapma (401→200, ayrı hata sınıfı) ama VERİ çıkarımı YOK | probable | OLASI | HIGH |
| inferential | salt boolean/timing/uzunluk farkı | theoretical | TEORİK | MEDIUM |

KURAL: `confirmed/DOĞRULANDI` demek için elinde GERÇEK çıkarılmış veri/etki olmalı ve `extracted_evidence` alanına o somut kanıtı (gördüğün veri parçası ya da screenshot ref) yaz. "1=1 vs 1=2 farklı byte" tek başına CRITICAL/DOĞRULANDI **DEĞİLDİR** → boolean SQLi'de `version()`/maskeli satır çıkarana kadar git; çıkaramıyorsan `inferential`/TEORİK bırak. `scripts/validate_finding.sh` bunu deterministik denetler; uymayan bulgu REDDEDİLİR.
