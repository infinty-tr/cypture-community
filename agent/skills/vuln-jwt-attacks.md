---
name: vuln-jwt-attacks
description: >
  JWT tabanlı kimlik/yetki token'larında imza ve claim doğrulama zayıflıklarını
  bulur. Ne zaman: istek/yanıtta JWT (üç base64url parça, nokta ile) görünce.
  alg:none, alg confusion (RS256→HS256), zayıf secret, kid traversal/SQLi, jku/x5u
  SSRF, jti replay, exp/nbf. Ana karar: değiştirilmiş token sunucuda KABUL edildi mi?
---

# 🔑 JWT SALDIRILARI — imzayı/claim'i doğrulamayan sunucuyu kanıtla

> **Tek cümle:** Token'ı decode etmek "kırmak" değildir; iş, KENDİ ürettiğin sahte/değiştirilmiş token'ın sunucuda geçerli sayıldığını ve yetkiyi yükselttiğini göstermektir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[access-control-reasoning]] [[chain-attack-builder]] [[vuln-ssrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE şu varsa test et: `Authorization: Bearer <eyJ...>`, cookie'de/JSON'da/localStorage'da `eyJ...` ile başlayan üç parçalı token, ya da OIDC `id_token`/`access_token`.
- Token decode edilince header'da `alg`/`kid`/`jku`/`x5u`/`jwk`, payload'da `role/sub/exp/nbf/iat/iss/aud/jti` gibi claim'ler görünüyor.
- SKIP: opak/rastgele session id (JWT değil); token'ı değiştirme/yetkin korunan endpoint erişimin yok; sadece imzalı ama yetki kararına etki etmeyen telemetri token'ı.

## 2. İNSAN MUHAKEMESİ
- JWT = sunucunun "sana güvendiği state'i" istemciye verip imza ile koruması. Geliştirici sık olarak: imzayı hiç doğrulamaz; `alg`'i istemciye bırakır (none/confusion); secret olarak zayıf bir string kullanır; `kid`'i dosya yoluna/DB sorgusuna/komuta sokar; `jku`/`x5u` ile anahtarı saldırgan URL'den çeker (SSRF); `exp`/`jti` kontrolünü atlar.
- Senin sorduğun: "Bu token'ın hangi parçası gerçekten korunuyor? Payload'ı değiştirip imzayı bozarsam/atlatabilirsem sunucu yutuyor mu? İmza anahtarını ben mi belirleyebiliyorum?"

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** geçerli token ile korunan endpoint'e istek → `cyp_send_request`, durum + kimlik/yetki yansımasını (yanıttaki kullanıcı adı, 200) kaydet, request_id sakla.
- **Decode:** `cyp_encode_decode` (base64url) ile header + payload aç. `alg` ne? `kid`/`jku`/`x5u` var mı? hangi claim'ler (role/sub/exp/aud) var?
- **Kademeli prob:**
  1. **İmza doğrulanıyor mu (TEK prob):** payload'da düşük riskli bir alanı boz, İMZAYI HİÇ değiştirmeden gönder. Hâlâ 200 + değişen değeri yansıtıyorsa → imza doğrulanmıyor sinyali (en hızlı kapı).
  2. **alg:none:** header `{"alg":"none"}`, imza parçası boş → kabul mü?
  3. **Yetki claim'i:** imza atlatılabiliyorsa `role:admin` / başka `sub` ile yükselme.
  4. **Anahtar-kaynaklı:** `kid`/`jku`/`x5u` varsa onu kontrol etme eksenine geç (§6).
- [[request-economy]]: her eksen ayrı hipotez, kör payload spreyleme yok; 401/403 alınca o ekseni kapat.

## 4. SİNYAL vs GÜRÜLTÜ
- **ADAY say:** imzası bozuk/yokken kabul edilen token; `alg:none` ile geçen istek; başka kullanıcının `sub`/`role`'ü ile gelen yetkili yanıt; public key'i HMAC secret olarak kullanınca geçerli imza (confusion); crack'lenmiş secret ile imzalanan token kabul; `kid` traversal ile bilinen-anahtar zorlanıp kabul; `jku`/`x5u` saldırgan URL'sine OOB callback + sahte anahtarla geçerli token.
- **SAYMA:** sadece decode edebilmen (herkes decode eder); 401/403 dönen denemeler; jenerik 500; WAF blok; `exp` geçmiş token reddi (normal davranış). Bunlar kanıt değil.

## 5. DOĞRULAMA KAPISI (kanıt)
- Üç token karşılaştır: (a) geçerli baseline, (b) değiştirilmiş+sahte/yok imza → KABUL, (c) negatif kontrol: imzayı rastgele boz → reddediliyor mu? Hepsi kabul ise imza tamamen yok sayılıyor; (b) kabul (c) red ise belirli bypass çalışıyor.
- Yetki yükselişini somut göster: düşük yetkili token → manipüle → yüksek yetkili kaynağa erişim (baseline 403, manipüleyle 200) → [[access-control-reasoning]].
- `jku`/`x5u` SSRF için: alanı kendi OOB host'una çevir, hedef-IP callback'i kanıtla → [[vuln-ssrf]]; sonra sahte JWKS ile geçerli token üret.
- N≥2 tekrar + `request_id`'leri raporla.

## 6. VARYASYON / BYPASS (bloklanınca)
- **alg:none** — header `{"alg":"none"}` (ve case varyantları `None`/`NONE`/`nOnE`), imza parçası boş; minimal kanonik: `eyJhbGciOiJub25lIn0.<payload>.`
- **alg confusion (RS256→HS256)** — sunucu RS256 bekliyor; `alg`'i HS256 yapıp sunucunun PUBLIC key'ini HMAC secret'ı olarak imzala. Public key'i JWKS endpoint'i / TLS sertifikası / `.well-known/jwks.json`'dan al; PEM whitespace/newline tam doğru olmalı.
- **Zayıf secret (offline brute)** — HS256 token'ı yakala, offline wordlist (jwt secret listeleri) ile crack et (sunucuya yük BİNDİRME — offline); kırılırsa istediğin claim'i imzala.
- **kid injection** — `kid`'i path traversal (`../../dev/null` → boş/bilinen anahtar), SQLi (`' UNION SELECT 'key'-- `), ya da komut bağlamına sok; sunucu kid ile dosya/DB'den anahtar çözüyorsa kontrol edilebilir-anahtar zorla.
- **jku / x5u SSRF** — header'daki anahtar-URL'ini saldırgan host'a çevir; sunucu oradan anahtar çekiyorsa sahte JWKS sun + OOB callback'i kanıtla → [[vuln-ssrf]].
- **jti replay** — aynı `jti`/token'ı tekrar oynat; replay koruması yoksa tek-kullanım kırık.
- **exp/nbf/iat manipülasyonu** — `exp`'i uzat, `nbf`'i geçmişe çek; imza atlatılabiliyorsa süre kontrolü anlamsız.
- **claim manipülasyonu gadget'ları** — `aud`/`iss` gevşekliği (başka client token'ı kabul), `role`/`scope`/`tenant` claim'lerini yükselt. Her biri ayrı hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- "Decode ettim → kırdım" YANLIŞ. Decode imzayı atlamaz; herkes decode eder.
- İmzayı gerçekte DOĞRULAYAN sunucuyu açık sanmak: bozuk token'ın 401 alıyorsa güvenli, bug yok.
- `alg:none`'u test edip 401 görmesine rağmen "muhtemelen vardır" demek — kanıtsız rapor etme.
- Public-key-as-HMAC denerken yanlış key formatı (PEM newline/whitespace/trailing) yüzünden başarısız olup "yok" demek; format hassas, dikkatli üret.
- `exp` geçmiş token'ın reddini "zafiyet yok" yerine doğru davranış olarak gör; tersine `exp` uzatılınca kabul edilirse o bulgu.
- `jku` URL'sinin yanıt vermesini SSRF sanmak; hedef-IP callback olmadan SSRF yok → [[vuln-ssrf]].
- Aynı `jti`'nin kabul edilmesini, oturum gerçekten geçersiz kılınmadıysa "replay" diye abartmak.

## 8. DURMA KRİTERİ
- KANITLANDI, KAPAT: sahte/değiştirilmiş token kabul edildi + yetki yükseldi + N tekrar + negatif kontrol (rastgele bozuk imza red) tutarlı.
- SİNYAL YOK, KAPAT: alg:none, confusion, zayıf secret, kid, jku/x5u, jti, exp eksenleri denendi; hepsi 401/403 → imza/claim doğrulaması sağlam.
- ŞÜPHELİ, İLERLE: bir eksende tutarsız davranış (bazen kabul) → daha fazla tekrar ile netleştir; jku/x5u'da OOB callback varsa sahte-JWKS adımına geç; uydurma.

## ÖZET — 5 KURAL
1. Önce baseline + decode; decode'u asla "exploit" sayma.
2. TEK prob: önce imza gerçekten doğrulanıyor mu (bozuk imza kabul mü)?
3. Sinyal = SAHTE token KABUL + yetki yükselişi, salt 200 değil.
4. Eksenleri sırayla (none → confusion → secret → kid → jku/x5u → jti/exp → claim), her biri hipotez.
5. Negatif kontrol (rastgele bozuk imza red) + request_id olmadan rapor yok.
