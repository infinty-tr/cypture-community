---
name: vuln-http-request-smuggling
description: >
  Zincirlenmiş bir front-end (proxy/LB/CDN) + back-end mimarisi varken uygulanır.
  Front-end ile back-end istek sınırını (Content-Length vs Transfer-Encoding) farklı
  yorumlarsa (CL.TE / TE.CL / TE.TE) smuggling mümkün olur. Ana karar: timing-bazlı,
  YIKICI OLMAYAN dedektörle backend'in sınırı yanlış böldüğü gözlendi mi.
---

# 🚚 HTTP REQUEST SMUGGLING (CL.TE/TE.CL/TE.TE) — proxy ve backend'i ayrı düşürmek

> **Tek cümle:** Front-end ve back-end aynı isteğin nerede bittiğine farklı karar verirse, saldırgan bir isteğin "kuyruğunu" sonraki kullanıcının isteğine kaçırabilir — ama önce GÜVENLİ, timing-bazlı dedeksiyonla varlığı doğrulanır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE **zincirlenmiş proxy** varsa: `Via`, `X-Cache`, CDN/LB header'ları, ya da front-end+back-end ayrı davranışı. HTTP/1.1 keep-alive akışı.
- Front-end ve back-end'in CL/TE'yi farklı işlemesi mümkün olmalı.
- SKIP: tek katman, saf HTTP/2 uçtan uca (mux farklı — yalnız H2 downgrade desync ayrı vaka), bağlantı keep-alive değil.

## 2. İNSAN MUHAKEMESİ
- HTTP/1.1 istek sınırı `Content-Length` VEYA `Transfer-Encoding: chunked` ile belirlenir. İkisi birden + uçların farklı önceliği = ihtilaf. Front-end bir sınır, back-end başka sınır görür → arta kalan byte'lar sonraki isteğe prepend olur.
- Geliştirici/altyapı: "her iki header da gelmez" varsaydı; RFC önceliğini katmanlar tutarsız uyguladı.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Normal istek gönder (Cypture send_request), normal yanıt süresini (RTT) N kez ölç.
- **TEK prob (timing, NON-DESTRUCTIVE):** Tek bir bağlantıda, backend'i eksik byte beklemeye düşürecek **kendi başına asılı kalan** bir istek gönder; ör. CL.TE dedektörü için TE'yi back-end görüp CL'yi front-end görsün diye düzenlenmiş, gövdesi backend'i bekletecek tek istek. Soket-only, victim trafiği yok.
- Gözlem: Yanıtın baseline'a göre belirgin **gecikmesi** (timeout'a yakın) → desync sinyali. Gecikme yoksa o varyant yok.

## 3.5 CYPTURE MOTORU İLE BYTE-EXACT GÖNDERİM (kritik — bu olmadan smuggling test EDİLEMEZ)
> Normal `cyp_send_request` Go net/http kullanır → **Transfer-Encoding'i normalize eder, gövdeyi
> dechunk eder, Content-Length'i yeniden yazar** = çakışan CL/TE tele ulaşmaz, smuggling İMKANSIZ olur.
> Bu yüzden smuggling isteğini **ham soketle byte-exact** göndermelisin:
- **Otomatik:** İsteğin başlıklarında `Transfer-Encoding` VARSA motor otomatik ham-sokete geçer (dechunk/normalize YOK).
- **Zorla:** Emin olmak için `cyp_send_request`'e **`raw_socket: true`** (veya `smuggle: true`) ekle → byte-exact,
  CL+TE birlikte korunur; yanıt best-effort parse edilir, ham gövde döner.
- **CRLF:** Satır sonları `\r\n` olmalı (motor normalize eder ama chunk gövdesini birebir gönderir).
- Örnek CL.TE dedektörü (front-end CL'yi, back-end TE'yi görür → back-end "0\r\n\r\n" sonrası `X`'i bekler → asılı kalır):
  ```
  POST / HTTP/1.1
  Host: <hedef>
  Content-Length: 6
  Transfer-Encoding: chunked

  0

  X
  ```
  `cyp_send_request(raw=<yukarıdaki>, host=<hedef>, port=<port>, raw_socket=true)` → **baseline RTT'nin çok üstünde gecikme = CL.TE desync sinyali.**
- TE.CL dedektörü (front-end TE'yi, back-end CL'yi görür): TE geçerli chunk + büyük CL ile back-end'i beklet. TE.TE: bir uçta yoksayılacak obfuscation'lı ikinci TE (`Transfer-Encoding: cow`, satır-katlama, dual TE).
- **Negatif kontrol:** Aynı isteği tutarlı/geçerli header'larla (yalnız CL ya da yalnız geçerli TE) gönder → gecikmemeli. Gecikme yalnız çakışmada çıkıyorsa sinyal gerçek.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** Dedektör isteği baseline RTT'nin çok üstünde, tekrarlanabilir gecikme üretiyor (backend eksik byte bekliyor); ve kontrol isteği gecikmiyor.
- **Gürültü:** Normal keep-alive gecikmesi, ağ jitter'ı, sunucu yavaşlığı, tek seferlik timeout. Smuggling DEĞİL.

## 5. DOĞRULAMA KAPISI (kanıt)
- Zincir: (1) baseline RTT dağılımı request_id'ler, (2) dedektör isteğinin tekrar tekrar (N≥3-5) anlamlı gecikme verdiği request_id'ler, (3) negatif kontrol: aynı istek geçerli/tutarlı header'larla gecikmiyor, (4) varyant ayrımı (CL.TE vs TE.CL hangisi timing veriyor).
- DİKKAT: Doğrulama **timing ile** kalsın; başka kullanıcıyı/uygulamayı bozacak gerçek smuggle payload'u (admin path enjekte, response-queue poisoning) bug bounty kapsamı/izni netleşmeden GÖNDERME. Yan-etkili exploitation yok.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Varyant ekseni:** CL.TE, TE.CL, TE.TE (her biri ayrı timing dedektörü).
- **TE obfuscation:** `Transfer-Encoding : chunked`, satır-katlama, sahte değer, dual TE — bir uçta yoksayılması.
- **CL manipülasyonu:** çift `Content-Length`, leading-zero, whitespace.
- **HTTP/2 downgrade:** H2 front-end → H1 back-end desync (H2.CL/H2.TE) timing denemesi.
- Tüm varyantlar timing-temiz ise dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- Normal keep-alive/ağ gecikmesini smuggling sanmak — negatif kontrol + tekrar şart.
- Tek seferlik timeout'tan sonuç çıkarmak (jitter).
- Front-end'in isteği reddetmesini (400) "desync" sanmak.
- Saf HTTP/2 uçtan uca'da klasik CL/TE araması.
- Hiç ikinci katman yokken (tek sunucu) smuggling iddiası.

## 8. DURMA KRİTERİ
- **Kanıtlandı (varlık), kapat:** Bir varyant tekrarlanabilir, baseline'dan ayrışan gecikme + temiz negatif kontrol verdi → güvenli dedeksiyonla doğrulandı, raporla (yıkıcı exploit denemeden).
- **Sinyal yok, kapat:** Tüm varyantlar baseline RTT içinde, tek katman, ya da H2 uçtan uca.
- **Şüpheli, ilerle:** Bir gecikme var ama kararsız → tekrar sayısını artır, obfuscation eksenini (§6) dene.

## ÖZET — 5 KURAL
1. İki katman (proxy+backend) yoksa SKIP.
2. Dedeksiyon GÜVENLİ ve timing-bazlı; yıkıcı/yan-etkili smuggle payload YOK.
3. Baseline RTT'yi ölç, sonra TEK asılı-kalan dedektör isteği gönder.
4. Kanıt = tekrarlanabilir gecikme + temiz negatif kontrol, tek timeout değil.
5. Normal keep-alive/jitter'ı smuggling sanma; emin değilsen kapat.
