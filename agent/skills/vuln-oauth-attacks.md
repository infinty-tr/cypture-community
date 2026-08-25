---
name: vuln-oauth-attacks
description: >
  OAuth 2.0 / OIDC akışlarında token/code hırsızlığına yol açan zayıflıkları
  bulur. Ne zaman: authorize/callback, redirect_uri, state, code/token görünce.
  redirect_uri bypass, state CSRF, code reuse/leak, implicit token leak, scope
  elevation, PKCE downgrade, account linking. Ana karar: credential saldırgana AKTI mı?
---

# 🪙 OAuth / OIDC SALDIRILARI — token/code'u saldırgana akıt

> **Tek cümle:** Akışın güvenliği "redirect_uri eşleşmesi + state + code tek-kullanım + PKCE"ye dayanır; iş, bu kontrollerden birini kırıp credential'ı kendi tarafına yönlendirdiğini kanıtlamaktır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-open-redirect]] [[access-control-reasoning]] [[chain-attack-builder]] [[vuln-csrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE şu varsa test et: `/authorize` veya `/oauth/...` endpoint'i; `redirect_uri`, `state`, `response_type`, `scope`, `code`, `access_token`, `code_challenge`/`code_verifier` parametreleri; bir callback URL'i.
- "Sign in with X" / SSO akışı, OIDC `id_token`, account-linking ("connect account") akışı.
- SKIP: OAuth yok, sadece tek bir login formu var; yönlendirme parametresini hiç etkileyemiyorsun.

## 2. İNSAN MUHAKEMESİ
- Provider, kullanıcının kimliğini doğrulayıp credential'ı (code/token) KAYITLI redirect_uri'ye gönderir. Geliştiriciler sık: redirect_uri'yi gevşek eşler (prefix/suffix/substring/subdomain/path/open-redirect zinciri); `state`'i hiç kontrol etmez (CSRF/login-CSRF/account-link); code'u tek kullanımlık yapmaz; implicit flow ile token'ı URL fragment'ında sızdırır; PKCE'yi opsiyonel bırakır (downgrade); code'u Referer/log ile dışarı kaçırır.
- Senin sorduğun: "Bu credential'ı, kullanıcının haberi olmadan benim kontrolümdeki bir hedefe akıtabilir miyim? Akışı CSRF ile kurbanın oturumuna bağlayabilir miyim?"

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** normal akışı `cyp_send_request` ile geçir; meşru `redirect_uri`, gelen `code`/`token`, `state`, `code_challenge` değerini ve callback davranışını kaydet, request_id sakla.
- **Kademeli prob:**
  1. **redirect_uri (TEK prob):** önce KENDİ host'un (`https://<hedef-evil>/cb`), sonra bypass varyantları (§6). Provider hata mı veriyor yoksa credential'ı oraya mı gönderiyor?
  2. **state:** state'i çıkar / sabitle / değiştir → akış yine tamamlanıyor mu (doğrulanmıyor = CSRF/login-CSRF/account-link mümkün)?
  3. **code reuse:** aynı `code`'u 2. kez exchange et → ikinci de token dönüyor mu?
  4. **code leak:** callback sayfasında dış kaynak/3p script var mı → code Referer/`document.referrer` ile sızar mı?
  5. **PKCE downgrade:** `code_challenge` olmadan veya `plain` method ile akış kabul ediliyor mu?
  6. **scope/implicit:** `scope`'a yeni izin ekle (sessiz onay?); `response_type=token` ile fragment token leak.

## 4. SİNYAL vs GÜRÜLTÜ
- **ADAY say:** değiştirilmiş `redirect_uri` ile `code`/`token` saldırgan host'a gitti; `state` olmadan/yanlış state ile akış tamamlandı (CSRF/account-link); aynı `code` ikinci kez kullanılınca token verildi; Referer/log'da code sızdı; PKCE atlandı; istenmeyen `scope` sessizce onaylandı; implicit token açık-redirect ile çalınabilir.
- **SAYMA:** provider'ın "invalid redirect_uri" hatası; jenerik 400; kendi sayfana dönen ama credential İÇERMEYEN redirect; state var ve doğrulanıyor; code ikinci exchange'de reddediliyor (doğru davranış).

## 5. DOĞRULAMA KAPISI (kanıt)
- **redirect_uri bypass:** değiştirilmiş URI ile başlayan akış sonunda callback'e DÜŞEN gerçek `code`/`token`'ı göster; baseline (meşru URI) vs saldırgan URI farkı + request_id. Open-redirect zinciriyse → [[vuln-open-redirect]] ile credential'ın attacker'a HOP ettiğini kanıtla.
- **state eksikliği:** state olmadan kurbanın oturumuna saldırgan code'unu bağlama (login-CSRF) ya da saldırgan hesabına kurban kimliğini bağlama (account linking) senaryosunu adım adım kanıtla → [[vuln-csrf]].
- **code reuse:** code'u 2 kez exchange et; ikincisi de token dönerse zaafı sabitle. N tekrar.
- **code leak:** callback'teki 3p isteğin Referer header'ında code'un gittiğini ham istekle göster.
- **PKCE downgrade:** `code_verifier` olmadan token alındığını göster (interception koruması kalkmış).

## 6. VARYASYON / BYPASS (bloklanınca)
- **redirect_uri whitelist bypass** — `?next=`/`//<hedef-evil>`, `https://<kayitli>.<hedef-evil>` (suffix), `<hedef-evil>.<kayitli>` (subdomain), path ekleme/traversal (`/cb/../redirect`), `@` userinfo (`https://<kayitli>@<hedef-evil>`), çift-kodlama, fragment/`#`, trailing slash farkı; kayıtlı URI'de açık-redirect parametresi → [[vuln-open-redirect]] zinciri.
- **state yok/doğrulanmıyor** — state'i çıkar/sabitle/önceki değeri tekrar oynat; login-CSRF, hesap bağlama abuse.
- **code leak (Referer / postMessage / log)** — callback sayfasında dış kaynak/analytics; `Referrer-Policy` zayıfsa code 3p'ye sızar.
- **implicit flow** — `response_type=token`/`id_token token`; token URL fragment'ında, açık redirect ile çalınabilir mi.
- **scope yükseltme / consent bypass** — `scope`'a admin/offline_access ekle; daha önce onaylanmış client'ta sessiz re-consent.
- **PKCE downgrade** — `code_challenge` parametresini düşür ya da `method=plain`; AS PKCE'yi zorunlu kılmıyorsa code-interception kapısı açık.
- **account linking abuse** — pre-account-takeover: saldırgan email'le hesap aç, kurban OAuth ile aynı email'e bağlanınca devral. Her eksen ayrı hipotez; sinyal yoksa kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- Normal akışın kendi callback'ine dönmesini "open redirect" sanmak — credential saldırgana gitmiyorsa bug yok.
- redirect_uri'yi değiştirip provider'ın hata vermesine rağmen "bypass olabilir" demek; kanıt yoksa rapor yok.
- `state` parametresini görüp doğrulanıp doğrulanmadığını test ETMEDEN "CSRF var" demek; tersi de geçerli — state yokluğunu görüp impact (account-link/login-CSRF) kurmadan rapor etmemek.
- Token'ı SENİN tarayıcında görüp "sızdı" sanmak — sızıntı, saldırgan kontrollü/üçüncü tarafa gitmektir.
- Code ikinci exchange'de reddedilmesini "reuse" diye yanlış raporlamak.
- PKCE varlığını görüp zorunlu olup olmadığını test etmeden "güvenli" demek (opsiyonelse downgrade var).

## 8. DURMA KRİTERİ
- KANITLANDI, KAPAT: code/token saldırgan kontrollü hedefe aktı VEYA state yokluğu ile account-link/login-CSRF adımı gösterildi VEYA code reuse/PKCE downgrade kanıtlandı + tekrar + request_id.
- SİNYAL YOK, KAPAT: redirect_uri sıkı eşleşiyor, state doğrulanıyor, code tek-kullanım, PKCE zorunlu → akış sağlam.
- ŞÜPHELİ, İLERLE: gevşek eşleşme var ama henüz credential akıtılmadı → open-redirect zincirini [[vuln-open-redirect]] ile sürdür.

## ÖZET — 5 KURAL
1. Hedef: credential'ı (code/token) saldırgana akıtmak; başka her şey yan kanıt.
2. Önce baseline akış, sonra TEK parametre (redirect_uri) değiştir.
3. Dört kontrolü ayrı ayrı kır: redirect_uri eşleşmesi, state, code tek-kullanım, PKCE.
4. Kendi callback'ine dönen meşru akışı "açık" sayma; impact (account-link/leak) kur.
5. Token sadece "saldırgan tarafına" gidince sızıntıdır; request_id ile kanıtla.
