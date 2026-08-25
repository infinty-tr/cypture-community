---
name: access-control-reasoning
description: >
  Yetkilendirme açıklarını (IDOR/BOLA, BFLA, Mass Assignment) AKILLICA bulmayı öğretir: önce
  "kim neyi yapabilmeli" modelini çıkar, sonra iki ayrı kimlikle sınırı kasten ihlal et. Kör ID
  enumerasyonu yerine ID formatını çözüp hedefli test; yetkinin NEREDE kontrol edildiğini muhakeme.
  En yaygın ve en yüksek etkili API açık ailesidir.
---

# 🔐 YETKİLENDİRME MUHAKEMESİ — IDOR / BOLA / BFLA / MASS ASSIGNMENT

> **Tek cümle:** Yetki açığı "bu kaynağa/işleve erişmemem gerekirdi, ama eriştim" demektir.
> Bulmak için önce KİMİN NEYE erişebileceğini modelle, sonra İKİ farklı kimlikle sınırı test et.
> Kör ID brute değil — modeli anla, hedefli ihlal et.

Bu aile (OWASP API #1 BOLA, #3 Mass Assignment, #5 BFLA) en sık ve en kolay otomatikleştirilen
ama en sık YANLIŞ yapılan sınıftır. Zayıf model ya hiç denemez ya da kör kör ID artırır. Doğrusu:
**iki gerçek kimlik + sahiplik/rol muhakemesi.**

İlişkili: [[data-flow-and-mental-model]] (kaynak/sahiplik), [[engine-mcp-contract]] (iki `sessionId`),
[[evidence-discipline]] (baseline 403 vs 200), [[request-economy]] (kör enum yasağı).

---

## 1. ÖNCE YETKİ MODELİNİ ÇIKAR

Test etmeden önce uygulamanın yetki haritasını yaz:

```
ROLLER        : guest / user / premium / merchant / admin / tenant-admin?
KAYNAK SAHİPLİĞİ: hangi obje kime ait? (sipariş→kullanıcı, dosya→workspace, kayıt→tenant)
SINIRLAR      : kullanıcı↔kullanıcı, tenant↔tenant, rol↔rol — hangisi geçilmemeli?
KONTROL NEREDE: yetki her endpoint'te mi, yoksa sadece UI'da mı kontrol ediliyor?
                (UI'da gizli ama API'de açık = klasik BFLA)
```

> İki test hesabı edin: **Kullanıcı A** ve **Kullanıcı B** (mümkünse farklı rol de). Cypture'da
> `sessionId="A"` ve `sessionId="B"` — cookie'ler karışmaz. (→ [[engine-mcp-contract]] §3)

---

## 2. IDOR / BOLA — nesne düzeyi yetki

```
ADIM 1: A olarak kendi kaynağına eriş, ID'yi ve yanıtı not et (baseline: 200 + A'nın verisi).
ADIM 2: A'nın TOKEN'ı ile B'nin ID'sini iste.
        Sinyal: 200 + B'NİN VERİSİ döndü → IDOR. (403/404 → kontrol var, normal.)
ADIM 3: Sadece okuma değil yazma/silme de dene (GET değilse PUT/DELETE/PATCH).
ADIM 4: Negatif kontrol: yetkisiz olması gereken gerçekten 403 mü? (yoksa her şey 200 ise
        belki auth hiç çalışmıyor — onu doğrula.)
```

**ID formatını ÇÖZ, kör artırma:**

```
Sıralı sayı (123,124)     → komşu ID'ler; az sayıda hedefli dene, binlerce DEĞİL.
UUID v4 (rastgele)        → tahmin edilemez; enum etme. ID'yi BAŞKA yerden sızdır
                            (response, JS, log, başka endpoint) sonra eriş.
UUID v1 (zaman+MAC)       → zaman bileşeni tahmin edilebilir olabilir.
MongoDB ObjectId          → ilk 4 byte timestamp → komşu objeler dar pencerede tahmin edilebilir.
Hash/encoded              → decode et (base64? → cyp_encode_decode), iç yapıyı anla.
```

> Kör 10.000 ID brute = token katili + WAF tetikler + çoğu zaman bulgu vermez. Önce formatı
> anla, sahiplik ihlalini BİRKAÇ hedefli istekle kanıtla. (→ [[request-economy]])

---

## 3. BFLA — fonksiyon düzeyi yetki

```
Soru: Admin/ayrıcalıklı bir işlevi normal kullanıcı çağırabilir mi?
ADIM 1: Düşük yetkili kullanıcıyla ayrıcalıklı endpoint'i çağır (/admin/*, /api/internal/*).
ADIM 2: Method/override dene: GET yerine POST/PUT/DELETE; X-HTTP-Method-Override: DELETE.
ADIM 3: Content-Type oyna (JSON↔form), bazı yetki katmanları sadece bir tipi kontrol eder.
Sinyal: düşük yetkili kimlikle ayrıcalıklı işlem GERÇEKLEŞTİ (durumu başka endpoint'ten doğrula).
```

---

## 4. MASS ASSIGNMENT / BOPLA — fazla alan enjeksiyonu

```
Soru: Objeyi güncellerken gönderemeyeceğim alanları gönderirsem kabul eder mi?
ADIM 1: Normal update isteğini gözle (örn. {name, email}).
ADIM 2: Ayrıcalıklı alan EKLE: {name, email, role:"admin", isAdmin:true, balance:99999,
        verified:true, tenantId:X, permissions:[...]}.
ADIM 3: Yeniden çek/relogin → alan GERÇEKTEN değişti mi? (yanıt "200" yetmez, durumu doğrula)
Sinyal: yetkisiz alan kalıcı olarak değişti → ayrıcalık yükseltme.
```

> Alan adlarını tahmin için: GET yanıtındaki tüm alanları, JS'deki model tanımlarını, farklı
> rol yanıtlarındaki ekstra alanları kaynak al. (→ [[data-flow-and-mental-model]])

---

## 5. KANIT FORMATI (yetki bulgusu için baseline şart)

```
[IDOR] GET /api/v1/orders/{id}
  Yetki modeli : sipariş kullanıcıya ait olmalı
  Baseline     : B token'ı ile B'nin siparişi → 200  (req_AAAA)   [normal]
  Baseline-neg : A token'ı ile B'nin siparişi → BEKLENEN 403
  İhlal        : A token'ı ile B'nin siparişi → 200 + B'nin verisi  (req_BBBB)
  Fark         : sahiplik kontrolü yok; A, B'nin verisini okudu
  Tekrar       : 3 kez, farklı ID çiftleriyle tutarlı
  Güven        : KANIT
```

---

## ÖZET — 5 KURAL

1. Önce yetki modelini çıkar (roller, sahiplik, sınırlar, kontrol nerede).
2. İki gerçek kimlik (Cypture'da iki sessionId) ile sınırı kasten ihlal et; baseline 403 olmalı.
3. ID formatını çöz, kör brute etme; UUID ise ID'yi sızdır, enum etme.
4. Sadece okuma değil yazma/silme/fonksiyon/fazla-alan da dene (IDOR+BFLA+Mass Assignment).
5. "200 döndü" yetmez — durumu başka endpoint'ten doğrula; baseline'sız bulgu yok.
