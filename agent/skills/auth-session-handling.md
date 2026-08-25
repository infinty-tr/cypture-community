---
name: auth-session-handling
description: >
  Authenticated (oturum açık) test için kimlik yönetimi: login akışını izleme, token/cookie'yi Cypture
  sessionId ile taşıma, süre dolunca yenileme, IDOR/BFLA için İKİ ayrı kimlik kurma, CSRF token akışı.
  Authenticated yüzey, anonim yüzeyden çok daha derindir — buraya erişmeden ciddi bulgu kaçar.
---

# 🔑 AUTHENTICATED OTURUM YÖNETİMİ

> **Tek cümle:** Gerçek değerli açıkların çoğu LOGIN'in arkasındadır. Oturumu doğru kurup taşımadan
> o yüzeyi test edemezsin. Token'ı Cypture `sessionId` ile yönet, süresini takip et, yetki testleri
> için iki ayrı kimlik hazırla.

İlişkili: [[engine-mcp-contract]] (sessionId/cookie jar), [[access-control-reasoning]] (iki kimlik),
[[vuln-jwt-attacks]], [[vuln-oauth-attacks]], [[vuln-auth-session]], [[evidence-discipline]].

---

## 1. LOGIN AKIŞINI İZLE VE ANLA

Test etmeden önce kimliğin NASIL kurulduğunu gözle (→ [[data-flow-and-mental-model]]):

```
[ ] Login isteği hangi endpoint? (POST /login, /api/auth, OAuth callback?)
[ ] Kimlik neyle taşınıyor? (Set-Cookie session / Authorization: Bearer JWT / API key header?)
[ ] CSRF token var mı? (login formunda gizli alan / ayrı /csrf endpoint?)
[ ] Token nerede, ne kadar geçerli? (exp claim / cookie Max-Age / sunucu session?)
[ ] Refresh mekanizması? (refresh_token / yeniden login gerekli?)
```

Bunu aktif firstphase.md UYGULAMA PROFİLİ + scope.md "Kimlik" alanına yaz.

---

## 2. OTURUMU CYPTURE'DA TAŞI

```
1. Login isteğini Cypture send_request ile at (scope.md'deki test kullanıcısıyla).
2. Yanıttaki Set-Cookie / token'ı YAKALA.
   - Cookie ise: aynı sessionId kullan, useCookieJar=true → otomatik taşınır (→ engine-mcp-contract §3).
   - Bearer/JWT ise: her isteğin raw'ına "Authorization: Bearer <token>" başlığını ekle.
3. Bir "kimlikli baseline" isteği at, gerçekten authenticated olduğunu DOĞRULA
   (örn. /me veya /profile → kullanıcının verisi dönüyor mu?). Dönmüyorsa oturum kurulmamış — durma noktası.
```

---

## 3. İKİ KİMLİK — yetki testleri için (kritik)

IDOR/BOLA/BFLA için iki ayrı, izole oturum şart (→ [[access-control-reasoning]]):

```
Kullanıcı A : sessionId="A"  (kendi token'ı, kendi kaynakları, ID'leri not et)
Kullanıcı B : sessionId="B"  (ayrı token, ayrı kaynaklar)
Mümkünse farklı ROL de: düşük-yetkili + yüksek-yetkili (BFLA için).
Kural: A'nın token'ıyla B'nin kaynağını iste → baseline 403 olmalı; 200+B verisi = IDOR.
Cypture cookie jar'ları sessionId ile ayrı tutar — karışmaz.
```

---

## 4. TOKEN SÜRESİ & YENİLEME

```
[ ] Token exp'ini izle; 401 görürsen "açık" sanma — önce oturum düştü mü kontrol et.
[ ] 401 ise: yeniden login / refresh at, yeni token'ı not et, kesilen testi KALDIĞI yerden sürdür.
[ ] Eski token'la yapılmış istekleri tekrar etme (→ [[request-economy]]) — sadece etkilenenleri yinele.
[ ] "logout sonrası token hâlâ geçerli mi?" bir TESTtir (→ [[vuln-auth-session]]) — kasıtlı dene.
```

---

## 5. CSRF TOKEN AKIŞI (state-changing isteklerde)

```
[ ] State değiştiren istek CSRF token istiyorsa: önce token'ı al (form/endpoint), isteğe ekle.
[ ] CSRF korumasını TEST etmek (token'ı çıkar/değiştir) ayrı bir testtir (→ [[vuln-csrf]]) — karıştırma.
[ ] SameSite cookie davranışını not et (Lax/Strict/None).
```

---

## 6. GÜVENLİK & ZARARSIZLIK

```
- Sadece scope.md'de izin verilen test hesaplarını kullan. Gerçek kullanıcı hesabı ele geçirme PoC'leri
  minimal kanıtla sınırlı (→ zararsızlık sınırı, core-contract).
- Rate-limit'i test ederken hesabı KİLİTLEME (→ [[vuln-auth-session]], [[vuln-rate-limit-resource]] uyarısı).
- Yakalanan token'ları findings dışında bir yere yazma; targets/ zaten .gitignore'da.
```

---

## ÖZET — 5 KURAL

1. Önce login akışını anla: endpoint, taşıyıcı (cookie/JWT), CSRF, süre, refresh.
2. Oturumu Cypture sessionId/cookie jar ile taşı; authenticated olduğunu /me ile doğrula.
3. Yetki testleri için iki izole kimlik (A/B, mümkünse farklı rol) kur.
4. 401'i "açık" sanma — oturum düştü mü bak, yenile, kaldığın yerden sürdür.
5. CSRF/logout-token gibi şeyler ayrı TESTtir — oturum kurmakla karıştırma; test hesabı dışına çıkma.
