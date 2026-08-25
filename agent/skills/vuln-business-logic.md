---
name: vuln-business-logic
description: >
  İş mantığı açık sınıfı (standalone playbook): iş akışı/adım atlama, negatif/taşma
  miktar, fiyat/toplam manipülasyonu, kupon/referral istismarı, replay, parametre
  kurcalama, birim/para birimi karıştırma, durum override. Ana karar: kuralı ihlal
  eden istek KALICI bir yetkisiz iş sonucu üretiyor mu (ikinci istekle doğrulanmış)?
---

# 🧩 İŞ MANTIĞI (BUSINESS LOGIC) — kuralı kasten ihlal et, kalıcı yetkisiz sonucu kanıtla

> **Tek cümle:** Geliştiricinin "kullanıcı bunu yapmaz" varsayımını kasten ihlal et; kanıt = ikinci bir istekle DOĞRULANMIŞ, kalıcı, yetkisiz iş sonucu (1 TL'ye sipariş, bakiye iadesi, atlanmış adım) — mekanik sinyal değil, mantıksal tutarsızlık.

İlişkili: [[business-logic-reasoning]] (varsayım çıkarma kontratı) [[vuln-race-condition]] (eşzamanlılık) [[access-control-reasoning]] [[data-flow-and-mental-model]] [[evidence-discipline]] [[engine-mcp-contract]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Bir AMAÇ taşıyan, değer/para/durum/akış yöneten her çok-adımlı işlem: ödeme/sepet, çekim/transfer, kupon/referral, abonelik/plan, randevu/rezervasyon, puan/ödül, onay iş akışları.
- İpuçları: client'tan gelen `price`/`amount`/`total`/`currency`/`qty`/`status`/`step` alanları; "şunu yapamazsınız" iş kuralları; sıralı adımlı sihirbazlar.
- SKIP: salt teknik açık (girdi→sorgu/komut → ilgili vuln-* playbook'u); saf eşzamanlılık-yarışı varsayımı → [[vuln-race-condition]]; saf yatay/dikey yetki → [[access-control-reasoning]]. Bu playbook KURAL ihlaliyle iş sonucu değiştirmeye odaklanır.

## 2. İNSAN MUHAKEMESİ
- Önce kuralları çıkar (kontrat → [[business-logic-reasoning]] §1): "miktar>0", "fiyatı sunucu belirler", "önce ödeme sonra teslim", "kupon bir kez", "indirim<fiyat". Her varsayım bir ihlal hipotezi.
- Geliştirici doğrulamayı CLIENT'a bırakmış veya sunucuda yeniden hesaplamamış olabilir; akış adımlarını state-machine ile zorlamamış olabilir.
- Asıl mesele: ihlal KALICI bir iş sonucu mu üretiyor (sipariş gerçekten oluştu, bakiye gerçekten değişti) yoksa sunucu sonradan mı düzeltiyor.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Akışı KURALA UYARAK bir kez tamamla (`cyp_send_request`); meşru sonucu (toplam, durum, bakiye, oluşan kaynak id) ve ara adımların request_id'lerini kaydet. Bu, "normal" referansı + negatif kontrolün temeli.
- **Tek prob (bir kuralı ihlal et):** Aynı akışı TEK bir varsayımı bozarak tekrarla:
  | Desen | İhlal probu | Beklenen yetkisiz sonuç |
  |---|---|---|
  | Fiyat/toplam manipülasyon | `price`/`total` alanını düşür | Düşük fiyatla sipariş |
  | Negatif/taşma miktar | `qty=-5`, `qty=0`, çok büyük, ondalık | Bakiye iadesi / taşma |
  | Adım atlama | Ara adımı atla, son adıma direkt POST | Ödemesiz teslim |
  | Durum override | `status=paid`/`shipped` gönder | Ödenmeden onaylandı |
  | Replay | Başarılı isteği aynen tekrar | Çift kredi/teslim |
  | Kupon/referral abuse | Aynı kupon N kez / stack / self-referral | Sınırsız indirim/ödül |
  | Birim/currency confusion | `currency=` ucuz birim, birim oyna | Daha az ödeme |
  | Parametre tampering | gizli `is_admin`/`discount`/`role` ekle | Yetkisiz ayrıcalık |

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** İhlal sonucu baseline'dan MANTIKSAL olarak sapan, istenmeyen bir DURUMA ulaştı (toplam negatif/aşırı düşük, ödemesiz teslim, kupon N kez geçti, bakiye arttı). Sapma deterministik.
- **Gürültü (aday DEĞİL):** Sunucu ihlali reddetti (400/"invalid")/değeri yeniden hesapladı (client fiyatını yok saydı); "işlem alındı" görünüp sonraki adımda düzeltildi; sepete eklendi ama satın ALINMADI; tek seferlik anomali tekrar etmiyor.

## 5. DOĞRULAMA KAPISI (kanıt — kalıcı sonuç, ikinci istekle teyit)
- **Kalıcılık:** "200 döndü" KANIT DEĞİL. İhlalden SONRA İKİNCİ bir istekle iş durumunu BAĞIMSIZ oku: sipariş listesi, bakiye, kupon kullanım, kaynak durumu → yetkisiz sonuç PERSİSTE oldu mu (`req` ile).
- **Sapma:** Baseline (kurala uygun) sonucu ↔ ihlal sonucu yan yana; fark mantıksal ve istenmeyen olmalı.
- **Negatif kontrol:** Aynı akış kurala uyunca normal sonuç (sunucu doğru hesaplıyor) → sapmanın ihlale bağlı olduğunu gösterir.
- **Tekrar:** 2-3 kez tutarlı üret.
- Her iddia: baseline request_id'leri + ihlal request_id + bağımsız doğrulama (ikinci okuma) request_id.

## 6. VARYASYON / BYPASS (ihlal reddediliyorsa)
- **Alan-konum ekseni:** Değeri body yerine query/header/cookie/JSON-nested'da gönder; sunucu bir yerde doğrulayıp diğerinde güveniyor olabilir.
- **Adım/sıra ekseni:** Adımları yeniden sırala, ara adımı atla, geri dön, iki adımı birleştir (state-machine boşluğu).
- **Encoding/tip ekseni:** String↔number, `"-5"` vs `-5`, scientific notation, leading-zero, çok-ondalık (yuvarlama/taşma), boolean coercion.
- **Birleşim ekseni:** Kupon+kupon stack, referral+kayıt çevrimi, çoklu indirim; tek tek tutmazsa kombinasyon.
- **Eşzamanlılık ekseni:** "Bir kez" kuralı sıralıda tutuyorsa → race ile sına ([[vuln-race-condition]]).
- 3-5 eksende kalıcı sapma yoksa "iş mantığı sinyali yok, sunucu kuralı uyguluyor" diye dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** "İstek kabul edildi"yi bulgu sanmak. Sepete ekleme/200 ≠ kalıcı yetkisiz sonuç — ikinci okumayla teyit et.
- **Geçici durumu kalıcı sanmak:** Sunucu ödeme/onay adımında düzeltiyor olabilir; akışı SONUNA kadar takip et.
- **Client değişikliğini sömürü sanmak:** Fiyatı body'de değiştirdin diye değil, sunucu o değeri KABUL edip işlediyse bulgu.
- **Reddedilen ihlali bulgu sanmak:** 400/"invalid"/yeniden-hesaplama = koruma çalışıyor.
- **Destrüktif test:** Gerçek para/sipariş/iade üreten ihlali körlemesine tekrarlama; non-destructive — test hesabı, tersine çevrilebilir adım, kanıtı minimumda tut, geri-alınamaz etkide DURMADAN önce teyidi al.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** İhlal kurala-uygun baseline'dan saptı + yetkisiz sonuç ikinci istekle PERSİSTE doğrulandı + negatif kontrol normal + tekrar üretildi.
- **Sinyal yok, kapat:** Tüm desen/eksen ihlalleri reddedildi/yeniden-hesaplandı; kalıcı sapma yok → sunucu iş kuralını uyguluyor.
- **Şüpheli, ilerle:** İhlal "kabul" görünüyor ama kalıcılık teyit edilmedi (akış yarıda) → akışı sonuna kadar takip et + bağımsız oku, sonra karar; token-pahalı, boşa harcama.

## ÖZET — 5 KURAL
1. Önce kuralları çıkar (varsayım kontratı), sonra TEK bir varsayımı ihlal et — kör spray değil.
2. Baseline'ı kurala uyarak al (negatif kontrol = sunucu doğru hesaplıyor); ihlali yanına koy.
3. Kanıt = kalıcı, yetkisiz iş sonucu; "200/kabul" değil, İKİNCİ istekle bağımsız doğrula.
4. Reddedilen/yeniden-hesaplanan ihlal bulgu DEĞİL; geçici durumu kalıcı sanma, akışı sonuna takip et.
5. Non-destructive ol; "bir kez" kuralını [[vuln-race-condition]]'a, saf yetkiyi [[access-control-reasoning]]'a devret.
