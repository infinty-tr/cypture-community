---
name: vuln-race-condition
description: >
  Race condition / TOCTOU sınıfı: "bir kez yapılabilir" varsayımı bir kontrol
  ile işlem arasındaki zaman penceresiyle kırılabiliyorsa uygulanır. Kupon/çekim/
  oy/stok gibi tek-kullanımlık etkiyi N kez tetiklemeye çalışır. Ana karar: sıralı
  N istek 1 etki üretirken eşzamanlı N istek >1 etki mi üretiyor?
---

# 🏁 RACE CONDITION (TOCTOU) — sıralı tek etki, eşzamanlı çok etki ise açıktır

> **Tek cümle:** Kontrol ile işlem arasındaki pencereye aynı isteği EŞZAMANLI sok; kanıt, sıralı baseline (N istek = N×tek-etki, limit tutar) ile eşzamanlı race (N istek = limit-aşımı) arasındaki ÖLÇÜLEBİLİR sapmadır.

İlişkili: [[business-logic-reasoning]] (varsayım çıkarma) [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] (`cyp_race_window_send`) [[request-economy]] [[vuln-business-logic]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Bir kaynağın "kontrol et → değiştir" şeklinde iki adımda işlendiği, tek-kullanım/limit varsayımı taşıyan akışlar: kupon kullan, bakiye çek/transfer et, stok düş, oy ver, davet/referral kabul, puan harca, OTP doğrula, like/follow, rate-limit'li işlem.
- İpuçları: "bu kupon zaten kullanıldı", "limit aşıldı", "günde 1 kez", bakiye/stok gibi paylaşılan sayaç; idempotency-key YOKLUĞU.
- SKIP: salt-okunur endpoint (durum değiştirmiyor); etki idempotent ve sayaç paylaşılmıyorsa; tek-kullanım varsayımı yoksa race'in anlamı yok → [[vuln-business-logic]].

## 2. İNSAN MUHAKEMESİ
- Geliştirici "önce bakiyeyi oku, yeter mi diye bak, sonra düş" yazmış ama bu iki adım atomik DEĞİL. İki istek aynı anda "yeter" kontrolünü geçip ikisi de düşerse → çift harcama (TOCTOU).
- Prepared/transaction + satır kilidi (`SELECT ... FOR UPDATE`) veya atomik `UPDATE ... WHERE balance>=x` kullansaydı kapalı olurdu; in-memory sayaç / oku-değiştir-yaz açık bırakır.
- Asıl mesele: pencere VAR mı? Kanıt mekaniği [[business-logic-reasoning]] §3 ile aynı — ama burada mekanik ölçüt: eşzamanlılık sapması.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline (sıralı):** Aynı işlemi `cyp_send_request` ile ARDIŞIK N kez (örn. 5) gönder. Beklenen: 1. başarılı, kalanları "zaten kullanıldı/limit" reddi. Her başarı/red için request_id + paylaşılan sayacın (bakiye/stok/kupon kullanım) son değerini not et. Bu, korumanın sıralıyken ÇALIŞTIĞINI gösterir — negatif kontrol budur.
- **Tek prob (eşzamanlı / single-packet):** Aynı isteği AYNI ANDA gönder:
  ```
  cyp_race_window_send  (single-packet / last-byte-sync, N=5..20 paralel)
  ```
  TCP/TLS el sıkışmasını önceden açıp son byte'ları senkron salar → pencere maksimum daralır. Yerel sayaç kalmazsa `cyp_batch_send` ile paralel gönder.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Sıralıda 1 başarı + 4 red iken eşzamanlıda 2+ başarı; VEYA sayaç limiti deterministik aşıldı (bakiye eksiye düştü, kupon 2 kez geçti, stok negatif, 1 oy 3 sayıldı). Sapma baseline'a göre net ve tekrar üretilebilir.
- **Gürültü (aday DEĞİL):** Eşzamanlıda da yalnız 1 başarı (koruma atomik) + N-1 red; tüm istekler 429/5xx (sadece rate-limit/yük, etki yok); "başarı" görünüp sayaç gerçekte değişmemiş; tek seferlik tutarsızlık tekrar etmiyor.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Sapma:** Baseline (sıralı) = 1 etki; race (eşzamanlı) = M>1 etki. İki koşunun request_id setleri + sonuçları yan yana.
- **Kalıcılık:** Etki gerçekten kaldı mı? İkinci bir istekle paylaşılan durumu YENİDEN OKU (bakiye/stok/kupon kullanım sayısı) → sapma persiste oldu mu. "200 döndü" değil, sayaç-aşımı kanıttır.
- **Tekrar:** Race koşusunu 2-3 kez yinele; M>1 tutarlı çıkmalı (race doğası gereği olasılıksal — ama tekrarla üretilebilmeli). Negatif kontrol = sıralı koşu hep limit tutuyor.
- Her iddia: baseline request_id seti + race request_id seti + doğrulama (yeniden-okuma) request_id.

## 6. VARYASYON / BYPASS (pencere açılmıyorsa)
- **Senkron ekseni:** `cyp_race_window_send` single-packet (HTTP/2 tek paket) ↔ last-byte-sync (HTTP/1.1) — hangisi pencereyi daha çok daraltıyorsa.
- **Paralellik ekseni:** N'i artır (5→20→50); bazı yarışlar yalnız yüksek eşzamanlılıkta açılır. Ama istek bütçesini gözet.
- **Hedef ekseni:** Aynı kaynağa İKİ FARKLI endpoint'ten eşzamanlı vur (örn. kupon-uygula + sipariş-tamamla) — tek endpoint kilitliyse çapraz-akış penceresi açık olabilir.
- **Connection-warmup:** İlk istekle DB bağlantısı/oturum ısınsın, sonra race; soğuk gecikme pencereyi bulanıklaştırır.
- 3-5 senkron/eşzamanlılık ekseninde sapma yoksa dürüstçe "race sinyali yok, koruma atomik" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **429/5xx'i "race başarısı" sanmak:** Rate-limit veya hata limit-AŞIMI değildir; sayaç fiilen aşılmadıysa bulgu yok.
- **"200 döndü" = çift etki sanmak:** Sunucu 200 dönüp işlemi sonradan reddediyor olabilir; paylaşılan durumu yeniden okuyup persiste olduğunu doğrula.
- **Baseline'sız iddia:** Sıralı negatif kontrol göstermeden "race var" deme — belki limit hiç yoktu (o zaman bu race değil, eksik limit → [[vuln-business-logic]]).
- **Olasılıksal tek atışı kanıt sanmak:** Tek koşuda 2 başarı tesadüf olabilir; tekrar üret.
- **Destruktif test:** Gerçek para/stok/veri tüketen akışta körlemesine yüksek-N race ATMA — non-destructive disiplin: önce düşük N, tersine çevrilebilir/test hesabı, geri-alınamaz etki varsa DURMADAN önce kanıtı minimumda tut.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Sıralı baseline limiti tutuyor + eşzamanlı race limiti aşıyor (M>1) + yeniden-okuma ile persiste + tekrar üretildi.
- **Sinyal yok, kapat:** Single-packet + yüksek-N + çapraz-endpoint denendi, eşzamanlıda da hep 1 etki → koruma atomik.
- **Şüpheli, ilerle:** Eşzamanlıda ara sıra 2 başarı görünüyor ama persiste/tekrar henüz yok → pencereyi daralt (single-packet, warmup), 1-2 hedefli koşu daha, sonra karar; token-pahalı, boşa harcama.

## ÖZET — 5 KURAL
1. Önce SIRALI baseline al (limit tutmalı = negatif kontrol); sonra EŞZAMANLI race at.
2. Eşzamanlılığı `cyp_race_window_send` ile single-packet/last-byte-sync yap — pencereyi daralt.
3. Kanıt = sıralı 1 etki ↔ eşzamanlı M>1 etki sapması, request_id setleriyle.
4. Etkiyi paylaşılan durumu YENİDEN OKUYARAK doğrula; "200" değil, sayaç-aşımı kanıttır.
5. Non-destructive ol: geri-alınamaz akışta düşük-N + test hesabı; tek atışı kanıt sanma, tekrar üret.
