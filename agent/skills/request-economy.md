---
name: request-economy
description: >
  İstek ve token ekonomisi. Aynı isteği tekrar atma (idempotency ledger), büyük yanıt/dosya
  çekme yasağı, dedup, durma kriterleri ve kısa çıktı disiplini. Her ajan her adımda buna uyar —
  amaç: maksimum kapsam, minimum israf. Zayıf modelde ve her runtime'da geçerli.
---

# 💸 İSTEK & TOKEN EKONOMİSİ — İSRAFA KARŞI

> **Tek cümle:** Her istek ve her token bir maliyet. Aynı bilgiyi iki kez alma, görmen
> gerekmeyeni çekme, cevabı bildiğin soruyu sorma. Maksimum kapsam, minimum harcama.

Zayıf model en çok şunları israf eder: aynı isteği tekrar tekrar atar, koca yanıt body'lerini
bağlama doldurur, aynı dosyayı defalarca okur. Bu modül bunları yasaklar.

---

## 1. İDEMPOTENCY LEDGER — aynı isteği iki kez atma

Her istekten önce kendine sor: **"Bunu zaten attım mı?"**

- Attığın istekleri kısa tut: `METHOD + path + ayırt edici param/payload` → request_id.
- Aynı (endpoint + payload) ikinci kez GEREKMEDİKÇE atılmaz. Gereken tek tekrar:
  baseline ortalaması (2-3 kez) veya bir sinyali doğrulama (bkz. [[baseline-and-signal]]).
- Yanıtı yeniden GÖRMEK için isteği tekrar atma → `cyp_get_request(ids=[id])` veya
  `cyp_search_history`. (bkz. [[engine-mcp-contract]])
- Bir bilgi `firstphase.md`'de zaten varsa yeniden keşfetme — OKU, kullan.

> Belirti: "az önce attığım isteği bir daha atayım" düşüncesi → DUR. Neden? Cevap zaten var.

---

## 2. YANITLARI KÜÇÜK TUT

- `cyp_send_request` ve `get_request`'te `bodyLimit` küçük (1000-1500). Tamamı nadiren gerekir.
- Büyük yanıtı (JS/HTML) bir kez al, İLGİLİ kısmı `firstphase.md`'ye özetle, ham gövdeyi
  bağlamda tutma. Tekrar gerekirse `bodyOffset` ile pencere oku.
- `get_request` varsayılan metadata-only — gövdeyi sadece gerçekten gerekince iste.
- Bir deseni aramak için tüm body'yi bağlama çekme → `cyp_search_history(pattern)` kullan.

---

## 3. DOSYA & DURUM EKONOMİSİ

- `firstphase.md`'yi her seferinde baştan sona okuma — sadece kendi bölümünü ve gereken tabloyu oku.
- Büyük JS/wordlist dosyalarını tekrar tekrar okuma; bir kez işle, çıkarımı state'e yaz.
- Yazarken üzerine ekle (append), tüm dosyayı yeniden üretme.
- Aynı analizi iki ajan yapmasın — orkestratör iş bölümünü net versin, çakışma = çift token.

---

## 4. DEDUP — tekrarı baştan ele

- Fuzz/keşif çıktısında tekrarlı endpoint/param'ı tekilleştir, sonra test et.
- Aynı kök neden farklı path'lerde aynı bulguyu veriyorsa → TEK bulgu (parametrik), 50 ayrı değil.
- Cross-agent: bir ajan bir teknolojiyi/secret'ı çözdüyse tekrar çözme, state'ten al.

---

## 5. DURMA KRİTERLERİ — ne zaman bırakılır

Bir input/endpoint/sınıf için testi BİTİR (daha fazla token harcama) şu durumda:

```
- 2 kapıdan geçen net bir bulgu bulundu VE kaydedildi → o sınıfı kapat, derinleşme gereksiz.
- Bağlam o sınıfı imkânsız kılıyor (teknoloji uyumsuz) → "SKIP: sebep" yaz, hiç atma.
- Birkaç teşhis prob'u net "sinyal yok" dedi → "❌ (denenenler, neden yok)" yaz, kapat.
- WAF/429 sürekli araya giriyor → dur, not düş, başka vektöre geç.
```

> "Belki bir payload daha" döngüsü token katilidir. Sinyal yoksa kapat, ilerle.

---

## 6. ÇIKTI DİSİPLİNİ — kısa yaz

- Gözlem loglarını yoğun/kısa tut: sayılar ve alıntılar, paragraf değil.
- Aynı şeyi hem state'e hem yanıta uzun uzun yazma — state tek gerçek kaynak.
- Düşünceni özetle, her ara adımı anlatma. Karar + kanıt yeter.

---

## ÖZET — 6 KURAL

1. Aynı isteği iki kez atma; yanıtı yeniden görmek için `get_request` kullan.
2. `bodyLimit` küçük; büyük gövdeyi bağlamda tutma, özetle.
3. State'ten oku, yeniden keşfetme; dosyayı tekrar tekrar okuma.
4. Dedup et; aynı kök neden = tek bulgu.
5. Sinyal yoksa/bağlam uymuyorsa kapat ve ilerle; "bir payload daha" yok.
6. Kısa yaz; karar + kanıt yeter.

## RE-KEŞİF MALİYETİNİ KIR — GÖRÜLEN-DESEN DEFTERİ ($WS/seen_patterns.jsonl)
Bir parametreyi/endpoint'i DERİN teste sokmadan önce defteri sor:
`bash scripts/fingerprint.sh seen "$WS/seen_patterns.jsonl" <class> <endpoint> [param]`
- exit 0 (GÖRÜLMÜŞ): bu desen başka yerde zaten DOĞRULANDI. Sıfırdan hunt YAPMA → TEK hızlı parametrik teyit at, çıkarsa `cyp_create_finding` + `scripts/propagate_finding.sh` ile parametrik yay (her varyantı ayrı bulgu YAPMA). Model döngüsü/istek harcama.
- exit 1 (YENİ): normal derin test akışını uygula.
Aynı yapıyı tekrar tekrar bulup raporlama; bir kez parametrik kaydet, yay. (Bütçe + gürültü düşer.)
