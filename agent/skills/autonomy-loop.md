---
name: autonomy-loop
description: >
  "İsim ver, gerisini kendi yapsın" otonom derinleşme döngüsü — plan→uygula→gözlemle→yeniden planla,
  öncelik-skorlu hipotez backlog'u, bütçe kapısı. VE "derin ama ucuz" maliyet modeli: mekanik işi
  modele değil script'lere yaptır, yapısal durumu seçici oku, en yüksek değerden başla. Orkestratörün motoru.
---

# 🔁 OTONOM DERİNLEŞME DÖNGÜSÜ + MALİYET MODELİ

> **Tek cümle:** Sistem boş durmaz; en yüksek-değerli hipotezi seçer, test eder, sonucu yüzey
> grafına işler, yeni hipotez türetir — kapsam/bütçe eşiğine kadar. Ama bunu UCUZ yapar: mekanik
> işi script'e yıkar, modele sadece kararı bıraktırır.

İlişkili: [[attack-surface-map]], [[scope-ingestion]], [[target-knowledge-base]], [[request-economy]],
[[run-metrics-and-selfreview]], [[baseline-and-signal]], [[evidence-discipline]], [[depth-calibration]].

---

## 💸 MALİYET MODELİ — "derin ama ucuz"in 7 kaldıracı

Derinlik pahalı OLMAK ZORUNDA DEĞİL. Token'ı yakan, modelin mekanik işi düşünerek yapmasıdır.
Kural: **Modeli sadece KARAR için kullan; geri kalan her şeyi deterministik araçlara yaptır.**

```
1. MEKANİK İŞ → SCRIPT.  Scope çekme, 5000 subdomain parse, dedup, skorlama, graf güncelleme
   bash/jq/grep ile yapılır. Model 5000 satırı OKUMAZ — script özet/üst-N döndürür.
2. YAPISAL DURUM → SEÇİCİ OKUMA.  surface.json'u tümüyle bağlama çekme; jq ile SADECE gereken
   dilimi sor ("auth endpoint'lerindeki test edilmemiş paramlar") → 20 satır, 5000 değil.
3. BÜTÇE KAPISI.  Her döngü turunda kalan istek/token bütçesini kontrol et; eşikte DUR.
   En yüksek değerden başladığın için erken durmak bile kapsamı maksimize eder.
4. KADEME YÖNLENDİRME.  Recon/triyaj/mekanik = UCUZ model. Sadece onaylanmış sinyalde derin
   muhakeme = GÜÇLÜ model. (→ core-contract çift-kademe)
5. ÖZETLE-AT.  Büyük yanıt/JS/HTML bir kez işlenir, çıkarım grafa yazılır, ham gövde atılır.
6. DEDUP.  tested.md + surface.json "tested" bayrağı → aynı şey iki kez işlenmez/atılmaz.
7. TEK-GEÇİŞ DAMITMA.  Recon/scope/surface BİR KEZ hesaplanır, kalıcı yazılır, tekrar kullanılır
   (→ [[target-knowledge-base]]). Re-run geniş değil DERİN gider.
```

> Sezgi: "model bir şey okuyup/sayıp/ayıklıyor" → bunu script yapmalı. "model bir şeye karar
> veriyor" → model yapmalı. Bu ayrım token faturasını 5-10x düşürür.

---

## 1. DÖNGÜ — plan → uygula → gözlemle → yeniden planla

```
HAZIRLIK (bir kez):
  scope-ingestion → scope.md + Cypture scope   (script, ucuz)
  recon → surface.json (yapısal yüzey)         (araçlar + script, ucuz)
  surface'tan hipotez backlog'u türet          (script skorlar, model rafine eder)

DÖNGÜ (bütçe bitene / kapsam dolana kadar):
  1. SEÇ    : backlog'tan EN YÜKSEK skorlu, test edilmemiş hipotezi al (jq, üst-1..N).
  2. YÜKLE  : hedefin DERİNLİK seviyesini belirle (→ depth-calibration: değer/sinyal tetikleyicisi
              varsa L3+ zorunlu), o sınıfın playbook'unu + ilgili surface dilimini yükle (seçici).
  3. UYGULA : baseline + tek prob + doğrulama kapısı (→ baseline-and-signal). Cypture send_request.
  4. GÖZLE  : sonucu surface.json'a işle (tested=true, sinyal?, kanıt?). tested.md'ye satır.
  5. REPLAN : sonuç YENİ yetenek/bilgi açtıysa (→ chain-attack-builder 5 soru) backlog'a yeni
              hipotez(ler) ekle, skorla. Sinyal yoksa o dalı kapat.
  6. BÜTÇE  : kalan bütçe < eşik? → DUR, metrik yaz (→ run-metrics-and-selfreview).
```

---

## 2. HİPOTEZ BACKLOG — öncelik skorlaması (script hesaplar)

Her hipotez bir satır (JSON/TSV). Skor = deterministik formül, model değil:

```
skor = (etki_ağırlığı × olasılık × erişilebilirlik) / maliyet
  etki        : RCE/ATO/SQLi=5, IDOR/SSRF=4, XSS/yetki=3, info=1
  olasılık    : sink eşleşmesi + tech matrisi uyumu (0.1–1.0)
  erişilebilir: auth gerektirmiyor / token elde / kapsam içi (0–1)
  maliyet     : tahmini istek sayısı (düşük = iyi)
En yüksek skordan işlenir. Backlog targets/<hedef>__<tarih>/backlog.tsv'de tutulur.
```

> Skorlamayı SCRIPT yapar (`sort -k`). Model sadece yeni hipotezin alanlarını (etki/sink) belirler.

---

## 3. DURMA / DOYMA KRİTERLERİ

```
DUR:
  - Bütçe eşiği aşıldı (istek/token).
  - Backlog'ta skor > eşik hipotez kalmadı (yüksek-değerli iş bitti).
  - Kapsam tamlık kontrolü geçti (→ run-metrics §3).
DERİNLEŞ (durma, devam):
  - Onaylanmış bir sinyal yeni saldırı yüzeyi açtı (chain) → en üst önceliğe koy.
```

---

## 4. ÇIFT-KADEME UCUZLUK (büyük vs küçük model)

```
Küçük model: döngü kısa adımlı, her adım script-destekli, az bağlam → ucuz + kararlı.
Büyük model: aynı döngü, ama onaylanmış sinyalde daha derin zincir muhakemesi → istek artmaz,
             sadece o tek adımda düşünce derinleşir. İkisinde de bütçe kapısı aynı.
```

---

## ÖZET — 6 KURAL

1. Modeli sadece KARAR için kullan; mekanik işi (parse/dedup/skor/graf) script'e yıka.
2. Durumu seçici oku (jq ile dilim), tümünü bağlama çekme.
3. Döngü: seç (en yüksek skor) → uygula (baseline+kanıt) → grafa işle → replan.
4. Bütçe kapısı her turda; en yüksek değerden başla, eşikte dur.
5. Sinyal yeni yüzey açarsa derinleş; açmazsa dalı kapat.
6. Tek-geçiş damıt, kalıcı yaz, re-run'da derinleş (geniş değil).
