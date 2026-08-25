---
name: depth-calibration
description: >
  Test fazının mantıksal kavrayışı — bir hedefe NE KADAR derine inileceğine karar verme. Yüksek-değerli
  yerlerde ZORUNLU derinleşme (deep-dive trigger), düşük-değerli yerlerde israf etmeme. L0–L4 derinlik
  seviyeleri, sinyalle yukarı/aşağı kalibrasyon. "Derine inmesi gereken yerde inmeme" hatasını bitirir.
  Hem bounty hem pentest. Web ve API test ajanlarının karar beyni.
---

# 🎚️ DERİNLİK KALİBRASYONU — nereye KAZ, nereye dokunma

> **Tek cümle:** İyi bir pentester her endpoint'e eşit zaman vermez. Login'e saatler, `/about`'a
> saniyeler ayırır. Sistemin en kritik becerisi: **yüksek-değerli yeri derinlemesine kazmak (asla
> yüzeysel geçmemek), değersiz yeri hızla kapatmak.** Full scan ≠ her şeye eşit; full scan = HER
> yere DOĞRU derinlik.

> En sık ve en pahalı hata (senin gördüğün): **derine inilmesi gereken yeri yüzeysel geçmek.**
> Bu skill onu yasaklar — aşağıdaki tetikleyiciler varsa derinleşme ZORUNLUDUR.

İlişkili: [[attack-surface-map]], [[autonomy-loop]], [[data-flow-and-mental-model]], [[business-logic-reasoning]],
[[access-control-reasoning]], [[attacker-mindset-and-persistence]], [[request-economy]], [[evidence-discipline]].

---

## 1. DERİNLİK SEVİYELERİ (L0–L4)

```
L0 — ATLA        : Test etme. Statik/CDN/değersiz, parametresiz+durumsuz, kapsam dışı.
L1 — YÜZEYSEL    : 1-2 teşhis probu. Düşük-değer ama tamamen yok sayılamaz (örn. basit GET sayfası).
L2 — STANDART    : İlgili sınıf checklist'i (baseline + her uygun vuln-* playbook'u, tek tur).
L3 — DERİN DALIŞ : Çok-vektör + bağlam manipülasyonu + OOB + manuel iş mantığı + zincir denemesi.
                   (YÜKSEK-DEĞER hedefler ve sinyal görülen her yer.)
L4 — EXHAUSTIVE  : Onaylanmış kritik bir yüzeyde her açıyı tüket (nadir; ATO/RCE adayı, para akışı).
```

Her hedefin ulaştığı seviye `surface.json` → `endpoint.depth_achieved` alanına yazılır.
**Kapsam kontrolü:** yüksek-değerli bir hedef L2'de kalmışsa kapsam EKSİKTİR (→ run-metrics §3).

---

## 2. DERİNE İNMEK ZORUNLU — deep-dive tetikleyicileri (L3+)

Aşağıdakilerden BİRİ varsa o hedef **asla** L1/L2'de bırakılmaz, L3 derin dalış yapılır:

```
DEĞER TETİKLEYİCİLERİ (ne yaptığına göre):
  □ Kimlik/oturum     : login, register, password reset, 2FA, token, SSO, OAuth
  □ Yetki sınırı      : başka kullanıcının/tenant'ın kaynağı, rol, admin/internal endpoint
  □ Para/değer akışı  : ödeme, transfer, bakiye, kupon, fiyat, sipariş, abonelik
  □ Durum değiştiren  : PUT/POST/DELETE + kalıcı etki (iş mantığı + race adayı)
  □ Karmaşık parser   : dosya upload, XML, deserialization, template, GraphQL, import/export
  □ Dış istek (SSRF)  : url/webhook/fetch/proxy/callback alanı
  □ Hassas veri       : PII, gizli, kredi, kişisel — IDOR/sızıntı etkisi yüksek

SİNYAL TETİKLEYİCİLERİ (gözleme göre — kısmi iz bile yeter):
  □ Baseline'dan herhangi bir anlamlı sapma (kod/süre/boyut/hata/yansıma)
  □ İlginç/ayrıntılı hata mesajı, stack trace, teknoloji sızıntısı
  □ Parametrenin yanıtta yansıması veya başka yerde görünmesi
  □ Olağandışı/tutarsız davranış (aynı girdi farklı sonuç, beklenmedik kod)
  □ "Burada bir şey var" hissi veren her şey → körelt değil, KAZ
```

> Kural: değer VEYA sinyal tetikleyicisi → L3. Tetikleyici yokken L3 yapma (israf). İkisi birden →
> L4 düşün. Tetikleyiciyi gördün ama yüzeysel geçtin = **sistemin en büyük başarısızlığı.**

---

## 3. İNME — düşük derinlik / kapat kriterleri

İsraf etmemek için (token ekonomisi), şu durumda L0/L1'de bırak:

```
□ Statik içerik, parametresiz, durum değiştirmeyen, yansıtmayan → L0/L1, kapat.
□ Pür bilgilendirme (versiyon, sürüm notu) → L1, not düş, geç.
□ L2 standart tur SİNYAL VERMEDİ ve değer tetikleyicisi YOK → kapat ("❌ denendi, temiz").
□ WAF her vektörü kesiyor + 2-3 bypass denendi → "ŞÜPHELİ", derinleşme, ilerle.
```

> Önemli denge: **değersiz yerde inme, ama değerli yerde sinyal yok diye de hemen bırakma** —
> değer tetikleyicisi varsa sinyal görünmese bile en az L3'ün manuel/mantık adımlarını DENE
> (blind/iş mantığı çoğu zaman sinyalsizdir → [[business-logic-reasoning]], [[out-of-band-testing]]).

---

## 4. KALİBRASYON DÖNGÜSÜ (her hedef için)

```
1. PUANLA   : surface.json + bölüm 2 tetikleyicileriyle başlangıç seviyesini belirle (L0–L3).
2. UYGULA   : o seviyeyi çalıştır (baseline → prob → playbook → derin vektörler).
3. AYARLA   : 
     Sinyal çıktı   → bir seviye YUKARI (L2→L3→L4), sonuna kadar git (→ attacker-mindset).
     Değer var, sinyal yok → L3'ün manuel/mantık/OOB adımlarını yine de dene, sonra dürüst kapat.
     Değer yok, sinyal yok  → bir seviye AŞAĞI, kapat, ilerle.
4. KAYDET   : endpoint.depth_achieved + sonuç → surface.json. Yüksek-değer L2'de kaldıysa İŞARETLE.
```

---

## 5. WEB vs API — full scan derinlik notları

```
WEB  : form/parametre başına bağlam (XSS bağlamı, SQLi, SSTI), state-changing akışlar L3,
       statik sayfalar L0/L1. Auth akışları her zaman L3+.
API  : her endpoint için BOLA/BFLA/Mass Assignment (yetki) NEREDEYSE HER ZAMAN L3 (API'nin kalbi),
       GraphQL/SSRF/JWT L3+, sağlık/ping/sürüm L1. İki kimlik şart (→ access-control-reasoning).
```

---

## ÖZET — 6 KURAL

1. Full scan = her şeye eşit değil, her yere DOĞRU derinlik (L0–L4).
2. Değer VEYA sinyal tetikleyicisi varsa derinleşme ZORUNLU (L3+) — asla yüzeysel geçme.
3. Değersiz + sinyalsiz yeri hızla kapat (L0/L1) — israf etme.
4. Değer var ama sinyal yoksa: manuel/mantık/OOB adımlarını yine de dene (blind/logic sinyalsizdir).
5. Sinyalde yukarı kalibre et, sonuna kadar git; değersiz+düz çizgide aşağı kalibre et.
6. depth_achieved'i kaydet; yüksek-değer hedef yüzeysel kaldıysa kapsam eksiktir, işaretle.
