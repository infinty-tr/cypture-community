---
name: run-metrics-and-selfreview
description: >
  Her koşumun verimliliğini ve kalitesini ÖLÇER ve rapordan önce ÖZ-DENETİM yaptırır. İstek/tekrar/
  şüpheli/kanıt sayıları (token görünürlüğü), kapsam tamlığı ve false-positive öz-kontrolü. Hem büyük
  hem küçük modelde israfı görünür kılar ve uydurma bulguları rapora girmeden eler. Orkestratör + reporter kullanır.
---

# 📈 KOŞUM METRİKLERİ & ÖZ-DENETİM

> **Tek cümle:** Ölçülmeyen iyileşmez. Her koşumun sonunda kaç istek attığını, kaçının tekrar
> olduğunu, kaç şüpheli/kanıt ürettiğini ölç; rapordan önce her bulguyu kendin eleştir. Token israfı
> ve halüsinasyon ancak görünür olunca azalır.

İlişkili: [[request-economy]], [[evidence-discipline]], [[baseline-and-signal]], [[workspace-protocol]].

---

## 1. KOŞUM METRİK PANOSU (aktif firstphase.md'ye, koşum sonu)

Orkestratör operasyon sonunda şu özeti yazar (ucuz, ama paha biçilmez görünürlük):

```
KOŞUM METRİKLERİ — <hedef> — <tarih>
  Toplam istek (Cypture)      : [N]            ← cyp_search_history / tested.md satır sayısı
  Tekrar/dedup engellenen   : [M]            ← tested.md'de "zaten var" diye atılmayanlar
  Test edilen endpoint      : [E]            Kapsanan subdomain: [S]
  Üretilen: KANIT bulgu     : [k]   ŞÜPHELİ : [ş]   ELENEN false-positive: [f]
  Atlanan (SKIP, sebepli)   : [a]
  Ortalama istek/bulgu      : [N/k]          ← düşükse verimli; çok yüksekse kör brute sinyali
  WAF/429 olayı             : [w]            ← yüksekse yavaşla, vektör değiştir
```

> **Yorum kuralı:** "istek/bulgu" oranı çok yüksek + bulgu az ise → kör brute yapılmış, gelecek
> koşumda daralt. Tekrar/dedup sayısı yüksekse → tested.md disiplini çalışıyor (iyi).

---

## 2. RAPOR ÖNCESİ ÖZ-DENETİM (her bulgu için — reporter)

Bir bulgu rapora girmeden ÖNCE kendine acımasızca sor (biri "hayır" → rapora GİRMEZ):

```
[ ] request_id var mı ve yanıtı GERÇEKTEN gördüm mü? (uydurma değil)
[ ] Baseline'dan ölçülebilir, SOMUT fark var mı? (200/WAF/403 tek başına değil)
[ ] N kez tekrarlandı + negatif kontrol geçti mi?
[ ] Bunu BİZZAT yeniden üretebildim mi? (üretemiyorsam → false-positive, ele)
[ ] Aynı kök nedenin kopyası mı? (parametrik tek bulgu olarak birleştir)
[ ] Etki gerçek mi, teorik mi? (teorik/info → severity'yi dürüst ver veya "ŞÜPHELİ")
```

Geçenler → rapor. Geçemeyenler → "ŞÜPHELİ" bölümü (rapora değil). (→ [[evidence-discipline]])

---

## 3. KAPSAM TAMLIK KONTROLÜ (rapor öncesi — orkestratör)

```
[ ] Her canlı subdomain en az bir kez profillenip ele alındı mı? (boş bırakılan var mı?)
[ ] Teknoloji matrisindeki ÖNCELİKLİ testler her hedefte yapıldı mı?
[ ] "ŞÜPHELİ" kalanlar belgelendi mi? (gelecek koşum için)
[ ] Atlananların HEPSİ sebepli mi? (sebepsiz atlama = kapsam boşluğu)
```

Eksik varsa rapora "Kapsanmayan / eksik" olarak DÜRÜSTÇE yaz — sessizce gizleme. (→ kör nokta dürüstlüğü)

---

## 4. ÇİFT-KADEME NOTU (büyük vs küçük model)

```
Küçük model: metrikler "kör brute" ve "halüsinasyon" eğilimini erken yakalar → kapıları sıkılaştır.
Büyük model: metrikler "gereksiz genişlik" (çok istek, az bulgu) eğilimini yakalar → derinliğe yönlendir.
Her ikisinde de hedef: yüksek "bulgu/istek" verimi, sıfır uydurma.
```

---

## ÖZET — 4 KURAL

1. Koşum sonu metrik panosunu yaz: istek/tekrar/şüpheli/kanıt/SKIP + istek-başına-bulgu oranı.
2. Rapor öncesi her bulguyu öz-denetimden geçir; geçemeyen "ŞÜPHELİ"ye gider.
3. Kapsam tamlığını kontrol et; eksikleri dürüstçe raporla, gizleme.
4. Metrikleri çift-kademe ayarı için kullan: küçük model → sıkılaştır, büyük model → derinleştir.
