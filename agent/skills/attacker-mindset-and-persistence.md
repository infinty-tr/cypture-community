---
name: attacker-mindset-and-persistence
description: >
  Gerçek bir saldırgan gibi düşünmeyi ve ERKEN PES ETMEMEYİ öğretir. Bir test ilk denemede
  başarısız görününce bırakma; neyin neden başarısız olduğunu anla, akıllıca varyasyon üret,
  birkaç açıdan dene — ama kör brute'a da kaçma. Dürüst tükenme ile tembel pes etme arasındaki
  farkı tanımlar. Token ekonomisiyle dengeli ısrar.
---

# 🥷 SALDIRGAN ZİHNİYETİ & ISRAR — ERKEN PES ETME

> **Tek cümle:** İlk payload "çalışmadı" demek "açık yok" demek değildir. Çoğu açık ikinci,
> üçüncü, beşinci varyasyonda ortaya çıkar. İnsan pes etmeden ÖNCE neyin engellediğini anlar
> ve onu aşar. Ama bu, kör brute-force değil — **akıllı, gerekçeli ısrar.**

Zayıf modelin iki uç hatası var: (1) tek deneme başarısızsa hemen bırakır ("hemen bırakıyor"),
(2) ya da kör kör 1000 payload atar. İkisi de yanlış. Doğrusu ortada: **az ama akıllı deneme,
her biri bir öncekinin neden başarısız olduğunu çözerek.**

İlişkili: [[baseline-and-signal]] (ne zaman dur), [[request-economy]] (token sınırı),
[[data-flow-and-mental-model]] (nereye bakılır).

---

## 1. "ÇALIŞMADI" DEĞİL — "NEDEN ÇALIŞMADI?"

Bir payload beklenen etkiyi vermediğinde DURMA, teşhis et:

```
Yanıt 400/422 mi?        → Girdi formatı reddedildi. Format/tip doğru mu? (JSON vs form, sayı vs string)
Yanıt 403/429/WAF mı?    → Engellendi, ama HEDEF DOĞRU olabilir. Encoding/vektör değiştir, yavaşla.
Yanıt 200 ama etki yok?  → Belki sink farklı; belki sonuç başka yerde çıkıyor (→ data-flow §3).
Payload encode mi edildi?→ Yansıma var ama escape'li → bağlam/encoding'i kır, başka bağlam dene.
Girdi hiç ulaşmadı mı?   → Belki yanlış parametre/endpoint; isteği gözden geçir.
Filtre mi var?           → Hangi karakter/kelime eleniyor? Onu izole et, etrafından dolan.
```

> Her başarısızlık BİLGİdir. Neyin engellediğini anlamadan bir sonraki denemeyi yapma —
> yoksa kör brute olur ve token yanar.

---

## 2. AKILLI VARYASYON — bir engeli aşmanın eksenleri

Bir vektör bloklandıysa, aynı şeyi tekrar atma; **ekseni değiştir** (her seferinde tek değişken):

```
ENCODING   : URL, double-URL, HTML entity, Unicode, base64, case (SeLeCt), null byte
BAĞLAM     : attribute'tan çık (">), script'e gir, event handler (onerror), JS string kır
KARAKTER   : yasaklı karakteri eşdeğeriyle değiştir (boşluk→/**/，→%09，'→')
SİNK YOLU  : aynı veriyi farklı endpoint/parametre/header/cookie üzerinden gönder
METOT      : GET↔POST, JSON↔form, method override (X-HTTP-Method-Override)
ZAMANLAMA  : blind ise time-based/out-of-band'e geç (görünür etki yoksa kanıtı dışarı taşı)
```

**Kural:** Her varyasyon bir HİPOTEZ test eder ("WAF boşluğu engelliyorsa /**/ ile geçer mi?").
Rastgele liste değil, hedefli sıçrama. (→ [[semantic-input-analyzer]] hipotez üretimi)

---

## 3. DERİNLİK SINIRI — ne kadar ısrar, ne zaman dur

İsrar ≠ sonsuz deneme. Her sinyal/vektör için makul derinlik:

```
SİNYAL VARSA (baseline'dan sapma görüldü):
  → Sonuna kadar git. Onaylanana ya da net çürütülene kadar bırakma. Bu YÜKSEK değerli an.
SİNYAL YOKSA (birkaç akıllı varyasyon, hiç sapma):
  → ~3-6 hedefli, FARKLI eksende deneme yeterli. Hepsi düz çizgi ise dürüstçe kapat:
    "❌ XSS — yansıma attribute'ta, " ve > encode ediliyor; 5 bağlam/encoding denendi, kaçış yok."
WAF SÜREKLİ ENGELLİYORSA:
  → 2-3 bypass denemesi sonrası dur, "ŞÜPHELİ: WAF arkasında, farklı vektör gerek" yaz, ilerle.
```

> "Bir payload daha" içgüdüsü: sinyal VARSA haklı, YOKSA token katili. Farkı sinyal belirler.

---

## 4. TEMBEL PES ETME vs DÜRÜST TÜKENME (kontrol listesi)

Bir testi kapatmadan önce kendine sor — biri bile "hayır" ise henüz tükenmedin:

```
[ ] Girdinin gerçekten ulaştığını ve sink'i doğru tahmin ettiğimi gözledim mi?
[ ] En az 2-3 FARKLI eksende (encoding/bağlam/sink) denedim mi, aynı şeyi tekrar değil?
[ ] Sonucun başka yerde çıkıp çıkmadığına baktım mı? (gecikmeli/çapraz/blind)
[ ] Engel WAF/filtre ise neyin elendiğini izole ettim mi?
[ ] Blind olabilecekse out-of-band denedim mi?
```

Hepsi "evet" ve hâlâ sapma yoksa → DÜRÜST TÜKENME, kapat ve gerekçeyi yaz.
Biri "hayır" ise → TEMBEL PES ETME, o adımı yap.

---

## 5. PARALEL HİPOTEZ — tek vektöre saplanma

İnsan bir açığa kilitlenip saatler harcamaz; birkaç hipotezi paralel taşır. Bir input için
2-3 muhtemel sınıf varsa, en ucuz+yüksek olasılıklıdan başla, sinyal vereni derinleştir,
vermeyeni hızla kapat. Sırayı [[data-flow-and-mental-model]]'deki sink tahmini belirler.

---

## ÖZET — 5 KURAL

1. "Çalışmadı" deme, "neden çalışmadı" diye teşhis et — her başarısızlık bilgidir.
2. Engeli aşmak için ekseni değiştir (encoding/bağlam/sink/metot), her seferinde tek değişken.
3. Sinyal varsa sonuna kadar git; yoksa 3-6 hedefli denemeyle dürüstçe kapat.
4. Kapatmadan önce tükenme kontrol listesini geç — biri "hayır" ise pes etme.
5. Tek vektöre saplanma; ucuz+yüksek olasılıklıdan başla, sinyal vereni derinleştir.
