---
name: data-flow-and-mental-model
description: >
  Bir insan pentester gibi DÜŞÜNMEYİ öğretir: her girdinin "ne aldığını, ne yaptığını, nereye
  gönderdiğini, sonucun nerede çıktığını" izleyip verinin tüm yolculuğunu kafanda kur; tek input'a
  değil TÜM sisteme bir zihinsel model çıkar. Payload atmadan ÖNCE bu muhakeme yapılır. Tüm test
  ajanlarının çekirdek düşünme katmanıdır.
---

# 🧭 VERİ AKIŞI & ZİHİNSEL MODEL — İNSAN GİBİ DÜŞÜN

> **Tek cümle:** Bir parametreye payload atmadan önce o verinin sistemin içinde NEREYE gidip
> NEREDE ortaya çıktığını kafanda canlandır. Sen payload fırlatan bir script değilsin;
> sistemin nasıl çalıştığını anlamaya çalışan bir mühendissin.

Zayıf modelin en büyük eksiği bu: bir input görür, ismine bakar, payload atar, sadece o anki
yanıta bakar, bir şey görmezse "yok" der ve geçer. İnsan böyle yapmaz. İnsan verinin **izini sürer.**

İlişkili: [[semantic-input-analyzer]] (tek input'un katman katman gözlemi) bu skill'in
mikroskobudur; bu skill ise tüm sistemin haritasıdır. [[evidence-discipline]], [[baseline-and-signal]].

---

## 1. HER GİRDİ İÇİN 4 SORU (önce bunu cevapla, sonra dokun)

```
1. NE ALIYOR?      → Bu girdi anlamca ne? (kimlik mi, miktar mı, dosya yolu mu, URL mi,
                      arama mı, HTML mi, komut parçası mı?) İSME DEĞİL davranışa bak.
2. NE YAPIYOR?     → Backend bu veriyle ne yapıyor? (DB sorgusu, dosya açma, şablon render,
                      başka servise istek, hesap, yetki kontrolü, log yazma?)
3. NEREYE GÖNDERİYOR? → Veri hangi "sink"e ulaşıyor? (SQL, OS shell, dosya sistemi, HTTP
                      isteği, template engine, deserializer, LDAP, XML parser, tarayıcı DOM?)
4. SONUÇ NEREDE ÇIKIYOR? → İşlenmiş veri NEREDE görünüyor? (aynı yanıt, başka endpoint,
                      başka kullanıcının ekranı, e-posta, PDF/export, log, admin paneli, async job?)
```

> Bu 4 soruyu cevaplayamıyorsan henüz saldırıya hazır değilsin → önce gözlemle (baseline + tipler).
> Cevaplar "BİLİNMİYOR" ise dürüstçe yaz, payload'la değil gözlemle netleştir.

---

## 2. KAYNAK → SİNK İZLEME (verinin yolculuğu)

Her girdi bir **kaynaktır (source)**. Tehlike, gittiği **sink**te doğar. İkisini bağla:

| Sink (varış) | Belirtisi | İlgili sınıf |
|---|---|---|
| SQL sorgusu | DB hatası, sıralama/filtre değişimi, sayıya duyarlılık | SQLi |
| OS shell | komut belirtisi, time delay | Command Injection |
| Dosya sistemi | path'e duyarlı, dosya içeriği döner | LFI/Path Traversal |
| Giden HTTP isteği | "url/fetch/webhook/import/callback" alanı | SSRF |
| Template engine | `{{7*7}}`→49, sunucuda işlenen ifade | SSTI |
| Tarayıcı DOM/HTML | yanıtta yansıma, encode YOK | XSS |
| Deserializer | base64/obje, "type" alanı | Insecure Deserialization |
| Yetki kontrolü | id/owner/role alanı | IDOR/BOLA/Mass Assignment |

**Kural:** Önce sink'i tahmin et (4 soru + gözlem), SADECE o sink'e uygun sınıfı test et.
Sink "tarayıcı DOM" ise SQLi deneme; "SQL" ise XSS wordlist'i atma. (→ [[baseline-and-signal]] §4)

---

## 3. "SONUÇ NEREDE ÇIKIYOR?" — zayıf modelin kaçırdığı yer

Bir payload'ın etkisi çoğu zaman **gönderdiğin yanıtta görünmez.** İnsan bunu bilir ve başka
yerlere bakar. Sen de bak:

```
ANINDA   : Gönderdiğin isteğin yanıtı (en bariz, ama çoğu zaman boş).
GECİKMELİ: Aynı veri başka bir endpoint'te (profil, liste, arama sonucu, dashboard).
ÇAPRAZ   : Başka bir KULLANICININ ekranında (stored XSS, IDOR ile sızan veri).
KANAL DIŞI: E-posta, PDF/CSV export, fatura, bildirim, webhook (giden istek), log dosyası.
ASENKRON : Bir job/queue sonradan işliyor (import, rapor üretimi) — etki dakikalar sonra.
BLIND    : Hiç görünmüyor → out-of-band (DNS/HTTP callback) ile kanıtla (Blind XSS/SSRF/SQLi).
```

> Stored bir payload bıraktıysan, onu nerede GÖRECEĞİNİ planla. "Yanıtta yok" ≠ "açık yok".
> Görmediğin yeri kontrol etmeden o testi kapatma. (→ [[evidence-discipline]] üç soru kapısı)

---

## 4. UYGULAMA ZİHİNSEL MODELİ (tek input değil, TÜM sistem)

Tek tek input'ları test etmeden önce uygulamanın ne olduğunu anla. Bu, hangi açıkların
mantıklı olduğunu belirler ve boşa token harcamanı engeller.

```
UYGULAMA NE İŞE YARIYOR? : (e-ticaret? SaaS? fintech? sosyal? CMS?)
ANA DEĞER/VARLIK NE?      : (para, kredi, abonelik, dosya, mesaj, kişisel veri?)
KULLANICI ROLLERİ?        : (guest/user/admin/merchant/tenant?) Aralarındaki sınır ne?
KİMLİK NASIL?             : (session/JWT/OAuth/API key?) Nerede doğrulanıyor?
KRİTİK İŞ AKIŞLARI?       : (kayıt, ödeme, transfer, yükleme, davet, şifre sıfırlama?)
GÜVEN SINIRLARI?          : (kullanıcılar arası, tenant'lar arası, iç/dış servis?)
DIŞ BAĞIMLILIKLAR?        : (S3, ödeme gateway, e-posta, 3rd-party API, webhook?)
```

Bu modeli `firstphase.md` UYGULAMA PROFİLİ bölümüne yaz. Her test ajanı bunu okuyup
**kendi hedefini bu modele göre önceliklendirir** — kör değil, bağlamlı.

---

## 5. ENDPOINT'İ AKIŞ İÇİNDE OKU (izole değil)

Bir endpoint'i tek başına değil, ait olduğu iş akışının parçası olarak gör:

```
Soru: Bu endpoint akışın neresinde? (öncesinde ne olmalı, sonrasında ne olur?)
Soru: Hangi durumu/objeyi değiştiriyor? (sepet, bakiye, rol, sahiplik?)
Soru: Bu adımı atlasam / sırasını bozsam / tekrarlasam ne olur? (iş mantığı → [[business-logic-reasoning]])
Soru: Bu objeye başka kim erişebilmeli, kim erişememeli? (yetki → [[access-control-reasoning]])
```

---

## 6. ÇIKTI — muhakemeyi yaz, sonra test et

Payload atmadan önce kısa bir "veri akışı notu" bırak (token-ucuz, ama yön verir):

```
[AKIŞ] /api/v1/orders?ref=  — 2026-..-..
  Ne alıyor   : sipariş referansı (string, kullanıcıya ait olmalı)
  Ne yapıyor  : DB'de ref ile sipariş çekiyor (gözlem: rakam→200, harf→400)
  Nereye      : muhtemelen SQL WHERE + sahiplik kontrolü?
  Sonuç nerede: yanıt gövdesi + ayrıca /receipt/{id} PDF'inde
  Hipotez     : (1) IDOR — başka ref → başkasının siparişi? (2) SQLi — ref tek tırnağa duyarlı mı?
  Test sırası : önce IDOR (ucuz, yüksek olasılık), sonra SQLi prob.
```

---

## ÖZET — 5 KURAL

1. Payload'dan önce 4 soru: ne alıyor / ne yapıyor / nereye gönderiyor / sonuç nerede çıkıyor.
2. Kaynağı sink'e bağla; sadece o sink'e uygun sınıfı test et.
3. Etki çoğu zaman o anki yanıtta değil — gecikmeli/çapraz/kanal-dışı/blind yerlere bak.
4. Önce uygulamanın zihinsel modelini kur (ne, kim, hangi akış, hangi sınır), state'e yaz.
5. Endpoint'i akış içinde oku; muhakemeyi kısa not et, sonra test et.
