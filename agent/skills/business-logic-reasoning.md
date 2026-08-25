---
name: business-logic-reasoning
description: >
  İş mantığı açıklarını AKIL YÜRÜTEREK bulmayı öğretir — bunlar tarayıcıyla/brute ile bulunamaz,
  uygulamanın AMACINI ve değer/para/durum akışını anlamayı gerektirir. Fiyat manipülasyonu, negatif
  değer, iş akışı atlama, race condition, kupon/limit istismarı, miktar/sahiplik karıştırma. En
  yüksek ödüllü, en az otomatikleştirilebilir sınıf.
---

# 💰 İŞ MANTIĞI MUHAKEMESİ — AKILLA BULUNUR, ARAÇLA DEĞİL

> **Tek cümle:** İş mantığı açığı, "geliştirici kullanıcının ŞUNU yapmayacağını varsaydı, ama
> ya yaparsa?" sorusudur. Hiçbir payload listesi bunu bulamaz — sadece uygulamanın ne yaptığını
> anlayıp kuralları kasten ihlal etmek bulur.

Bunlar zayıf modelin en çok kaçırdığı ve en değerli açıklardır, çünkü "hata mesajı / time delay /
yansıma" gibi mekanik sinyal yoktur. Sinyal **mantıksal tutarsızlıktır**: 100 TL'lik ürünü 1 TL'ye
aldın, olmaması gereken bir duruma ulaştın, başkasının adına işlem yaptın.

İlişkili: [[data-flow-and-mental-model]] (uygulama modeli), [[access-control-reasoning]] (yetki),
[[evidence-discipline]] (kanıt), [[engine-mcp-contract]] (race için `cyp_race_window_send`).

---

## 1. ÖNCE KURALLARI ÇIKAR (ihlal edebilmek için kuralı bil)

Bir akışı test etmeden önce geliştiricinin örtük varsayımlarını yaz:

```
AKIŞ: Satın alma
  Varsayım 1: miktar pozitiftir         → ya negatif/0/ondalık/çok büyük gönderirsem?
  Varsayım 2: fiyatı sunucu belirler     → ya fiyatı ben gönderirsem / değiştirirsem?
  Varsayım 3: önce ödeme, sonra teslim   → ya adımı atlar/sırasını bozarsam?
  Varsayım 4: kupon bir kez kullanılır   → ya aynı anda 10 kez gönderirsem (race)?
  Varsayım 5: indirim ürün fiyatından az → ya indirim > fiyat → negatif toplam → bakiye iadesi?
```

Her varsayım bir test hipotezidir. "Geliştirici neyi ENGELLEMEYİ unuttu?" diye sor.

---

## 2. İŞ MANTIĞI AÇIK DESENLERİ (reasoning kartları)

| Desen | Soru | Nasıl test | Sinyal (mantıksal) |
|---|---|---|---|
| **Parametre/fiyat manipülasyonu** | Fiyatı/toplamı ben mi gönderiyorum? | `price`, `amount`, `total` alanını düşür/değiştir | Düşük fiyatla sipariş kabul edildi |
| **Negatif/sınır değer** | Miktar/tutar negatif olabilir mi? | `qty=-1`, `amount=0`, ondalık, taşma | Bakiye arttı / iade üretildi |
| **İş akışı atlama** | Adımı atlayabilir miyim? | Ara adımı atla, son adıma direkt git | Ödemesiz teslim / doğrulamasız erişim |
| **Durum manipülasyonu** | Durumu geri/ileri zorlayabilir miyim? | `status=shipped`/`paid` gönder | Ödenmeden "paid" oldu |
| **Tekrar/replay** | Aynı işlemi tekrar edebilir miyim? | Başarılı isteği tekrar gönder | Çift kredi / çift teslim |
| **Kupon/promosyon istismarı** | Kupon mantığı sömürülebilir mi? | Aynı kupon defalarca, kombinasyon, stack | Sınırsız indirim |
| **Limit bypass** | Limit nerede kontrol ediliyor? | İstemci limitini aş, eşzamanlı gönder | Limit üstü işlem |
| **Miktar/birim karıştırma** | Birim/para birimi değiştirilebilir mi? | currency=farklı, birim oyna | Daha az ödeme |

---

## 3. RACE CONDITION — eşzamanlılık muhakemesi

"Bir kez yapılabilir" varsayımı çoğu zaman eşzamanlı isteklerle kırılır (TOCTOU):

```
Aday akışlar: kupon kullan, bakiye çek, stok düş, davet kabul, oy ver, puan harca.
Soru: kontrol ile işlem arasında zaman penceresi var mı?
Test: aynı isteği EŞZAMANLI N kez gönder → cyp_race_window_send (→ engine-mcp-contract §6).
Sinyal: tek kullanımlık şey N kez işledi (çift harcama, stok eksiye düştü, kupon N kez geçti).
Kanıt: baseline (1 istek = 1 etki) vs race (N eşzamanlı = >1 etki), tekrar üret.
```

> Race testi token-pahalıdır — sadece net bir "tek kullanım" varsayımı + değer akışı varsa yap.

---

## 4. NEGATİF KONTROL (iş mantığında false-positive'den kaçın)

İş mantığı bulgusu "işlem kabul edildi" değil, **istenmeyen DURUMA ulaşıldı** demektir:

```
[ ] Gerçekten kalıcı bir etki mi? (sepete eklendi ≠ satın alındı — relogin/yeniden çek, doğrula)
[ ] Sunucu sonradan reddediyor mu? (ödeme adımında düzeltiliyor olabilir — sonuna kadar takip et)
[ ] Etki ölçülebilir mi? (bakiye/sipariş/durum gerçekten değişti mi — başka endpoint'ten doğrula)
```

Doğrulanmadıysa "ŞÜPHELİ"ye yaz, bulgu deme. (→ [[evidence-discipline]])

---

## 5. ÇIKTI

```
[İŞ MANTIĞI] Sipariş akışı — negatif miktar
  Kural (varsayım) : miktar > 0
  İhlal            : POST /cart {item:X, qty:-5}  → req_BBBB
  Baseline         : qty:1 → toplam +100  (req_AAAA)
  Sonuç            : qty:-5 → toplam -500 → bakiyeye 500 iade  (req_CCCC ile doğrulandı)
  Etki             : sınırsız para üretimi
  Tekrar           : 3 kez, tutarlı
  Güven            : KANIT
```

---

## ÖZET — 5 KURAL

1. Önce geliştiricinin örtük varsayımlarını çıkar; her varsayım bir ihlal hipotezidir.
2. Desenleri uygula: fiyat/negatif/akış atlama/durum/replay/kupon/limit/birim.
3. "Tek kullanımlık" varsayımını eşzamanlılıkla (race) sına — ama sadece değer akışı varsa.
4. Bulgu = istenmeyen DURUMA ulaşmak; kalıcı etkiyi başka endpoint'ten doğrula, yoksa "şüpheli".
5. Mekanik sinyal yok — sinyal mantıksal tutarsızlıktır; akıl yürüt, brute etme.
