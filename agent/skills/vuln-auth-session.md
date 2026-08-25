---
name: vuln-auth-session
description: >
  Password reset, 2FA bypass ve session yönetimi zayıflıklarında hesap ele
  geçirme (ATO) yolu arar. Ne zaman: reset/forgot, OTP/2FA, login/logout,
  remember-me, cookie güvenlik bayrakları akışları görünce. Ana karar:
  kanıtlanabilir bir ATO yolu var mı?
---

# 🔐 KİMLİK & OTURUM — password reset / 2FA bypass / session

> **Tek cümle:** Bu sınıf "hesabı ele geçirebilir miyim?" sorusudur; teorik zayıflık değil, baseline'dan kurban hesabına ulaşan SOMUT bir adım zinciri ararsın.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[business-logic-reasoning]] [[access-control-reasoning]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE şu varsa test et: `forgot-password`/`reset` akışı + reset token; 2FA/OTP doğrulama adımı; login/logout + session cookie/token; "remember me" / kalıcı oturum; oturum cookie'sinin güvenlik bayrakları.
- SKIP: kimlik akışı yok, ya da yalnızca tek bir public sayfa. Test ortamı izinli değilse (canlı kullanıcı hesabı) DUR.

## 2. İNSAN MUHAKEMESİ
- Reset token = geçici, tek-kullanımlık, tahmin edilemez (yeterli entropi) olmalı ve kullanıcıya BAĞLI mailden gitmeli. 2FA = ikinci faktör atlanamamalı. Session = login'de yenilenmeli, logout'ta sunucuda gerçekten geçersiz olmalı, cookie HttpOnly+Secure+uygun SameSite taşımalı.
- Geliştirici sık: reset token'ı zayıf/öngörülebilir (timestamp/incremental/md5(email)) üretir, Host header'a güvenip linki zehirler, token'ı expiry/reuse korumasız bırakır; 2FA'yı response manipülasyonu/flow-skip ile atlatılır kılar; session'ı login'de yenilemez (fixation), logout sonrası token'ı sunucuda iptal etmez; remember-me token'ını öngörülebilir/iptal-edilemez yapar.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- Baseline: KENDİ kontrolündeki iki test hesabıyla normal akışı geçir (`cyp_send_request`); reset token'ın biçimi/uzunluğu/entropisi, 2FA adımının response'u, login öncesi/sonrası session değerini, Set-Cookie bayraklarını kaydet.
- İlk TEK prob (yıkıcı OLMAYAN seç): reset isteğinde `Host`/`X-Forwarded-Host`/`X-Forwarded-Server` başlığını saldırgan host yap → dönen mail linkinde bu host yansıyor mu? (host-header poisoning teşhisi, rate-limit'e dokunmaz.)

## 4. SİNYAL vs GÜRÜLTÜ
- ADAY say: reset link'in saldırgan host içermesi; token'ın tahmin edilebilir/kısa/sıralı olması; kullanılmış/expired token'ın hâlâ çalışması; başka kullanıcının token'ını talep edebilme; 2FA response'unda `success:false`→`true` veya `enabled:true`→`false` manipülasyonu ile geçiş; 2FA adımını atlayıp sonraki endpoint'e doğrudan gidiş (flow-skip); OTP'de rate-limit yokluğu; login'de session id'nin DEĞİŞMEMESİ (fixation); logout sonrası eski token'ın hâlâ 200 alması; Set-Cookie'de `HttpOnly`/`Secure` eksikliği veya `SameSite=None` (CSRF/XSS-theft yüzeyi); remember-me token'ın öngörülebilir/iptal-edilemez olması.
- SAYMA: jenerik 200, "token expired" mesajı (beklenen), kendi hesabında çalışan normal akış, WAF blok.

## 5. DOĞRULAMA KAPISI (kanıt)
- **ATO zinciri:** A hesabıyla başlat → zaafı kullan → B (kurban) hesabına eriş/şifresini değiştir. Baseline (zaafsız) vs exploit farkı + `request_id`.
- **Session fixation:** login ÖNCESİ session id = login SONRASI id ise iki request_id ile kanıtla (sunucu yenilemiyor).
- **Logout/invalidation:** logout sonrası eski token ile korunan kaynağa eriş → hâlâ 200 ise sabitle; tek-kullanım: aynı reset token'ı 2. kez kullan → hâlâ kabul mü?
- **Cookie güvenliği:** Set-Cookie başlığını oku; `HttpOnly` yoksa XSS→theft, `Secure` yoksa MITM, `SameSite=None`+CSRF yüzeyi — bayrak eksikliğini ham başlıkla göster (tek başına düşük etki; bir XSS/CSRF ile zincirle).
- **Reset token entropi:** ≥3 token topla; sıralı/zaman-bağlı/düşük-charset ise tahmin edilebilirliği göster (gerçekten bir kurban token'ı türetebiliyorsan kanıt; yoksa "zayıf görünüm").
- N≥2 tekrar + negatif kontrol (geçersiz token/yanlış faktör reddediliyor mu?).

## 6. VARYASYON / BYPASS (bloklanınca)
- **Reset token** — host-header poisoning (`X-Forwarded-Host`/`Referer`-based link), token entropy/tahmin (sıralı, timestamp, `md5(email)`), reuse (tek-kullanım yok), expiry yokluğu, başka kullanıcının token'ını talep (`email=victim` ama oturum saldırganda), token'ı response'ta sızdırma.
- **2FA bypass** — response manip (`enabled:false`/`verified:true`), flow-skip (OTP adımını atlayıp post-2FA endpoint'e doğrudan), backup-code/recovery zayıflığı, 2FA'yı oturum sırasında kapatma yetkisi, "remember device" token'ın zayıflığı.
- **OTP brute** — DİKKAT: rate-limit testini ÇOK az dene; yıkıcı (hesap kilitleme). Önce tek istekle "limit var mı" gözle, varsa DURMA.
- **Session** — fixation (login'de yenilenme yok), logout sonrası geçerlilik (server-side invalidation yok), eşzamanlı oturum/iptal, "remember me" token öngörülebilirliği/iptal-edilememesi, cookie bayrak eksikliği (HttpOnly/Secure/SameSite), JWT ise `alg:none`/zayıf imza/`exp` yokluğu. Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Rate-limit denerken hesap kilitlemek** — YIKICI; gerçek kullanıcıya zarar. Az dene, limit görünce dur; brute'u "başarısız" diye değil "test edilmedi/limit var" diye raporla.
- Teorik zayıflığı (ör. "token kısa görünüyor", "HttpOnly yok") tek başına KANITSIZ ATO diye raporlamak — gerçek tahmin/ele geçirme ya da somut zincir (XSS→cookie) göstermeden değil.
- "token expired" mesajını zafiyet sanmak; bu beklenen doğru davranış.
- 2FA/response'u istemci tarafında değiştirip UI'ın geçmesini "bypass" sanmak — sunucu kararını değiştirmediyse bug değil; sonraki korunan isteğin gerçekten 200 aldığını göster.
- Logout sonrası cookie'nin tarayıcıda durmasını "geçersizleştirilmedi" sanmak; asıl test sunucunun token'ı hâlâ KABUL edip etmediğidir.
- Tek-kullanım token'ı bir kez kullanıp "reuse" iddia etmek — ikinci kullanımın gerçekten kabul edildiğini göster.

## 8. DURMA KRİTERİ
- KANITLANDI, KAPAT: baseline'dan kurban hesabına ulaşan uçtan uca ATO zinciri (veya kanıtlı fixation/reuse/host-poisoning) + tekrar + negatif kontrol + request_id.
- SİNYAL YOK, KAPAT: reset token güçlü/tek-kullanım/host-bağımsız, 2FA atlanamıyor, session login'de yenileniyor ve logout iptal ediyor, cookie bayrakları tam.
- ŞÜPHELİ, İLERLE: bir eksende tutarsızlık var ama ATO tamamlanmadı → iş mantığını [[business-logic-reasoning]], yetkiyi [[access-control-reasoning]] ile derinleştir; cookie bayrak eksikliğini XSS/CSRF ile zincirle; rate-limit'i ZORLAMA.

## ÖZET — 5 KURAL
1. Hedef tek: kanıtlanabilir hesap ele geçirme (ATO) zinciri, teori değil.
2. Önce kendi iki test hesabınla baseline; yıkıcı olmayan host-header probu ile başla.
3. Rate-limit/OTP brute'unu ÇOK az dene; kilitleme riskinde DUR.
4. Sunucu kararını değiştirmeyen istemci-tarafı oynama bypass değildir; fixation/logout-invalidation/reuse'u sunucu davranışıyla kanıtla.
5. Cookie bayrak eksikliği tek başına düşük etki — bir XSS/CSRF ile zincirle; negatif kontrol + request_id olmadan ATO raporlama.
