---
name: vuln-saml-xml-signature
description: >
  SAML SSO / XML imza doğrulama sınıfı: IdP'nin imzaladığı assertion'ı SP kabul
  ederken imza-gövde bağını gevşek doğruluyorsa uygulanır. XML Signature Wrapping
  (XSW), imza dışlama, yorum-enjeksiyonu, imzasız-assertion kabulü, recipient/audience
  bypass. Ana karar: SP imzayı doğru gövdeye GERÇEKTEN bağlıyor mu, yoksa ben
  kimliği değiştirip imzayı orijinal bırakınca da "geçerli" mi diyor?
---

# 🪪 SAML / XML SIGNATURE WRAPPING — imzalı assertion'ı yeniden konumlandır, SP yanlış gövdeyi okusun

> **Tek cümle:** İmza geçerli kalsın ama SP'nin OKUDUĞU assertion benim kontrolümde olsun; kanıt, manipüle edilmiş response'la BAŞKA kullanıcı/admin oturumu açmaktır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-xxe]] [[access-control-reasoning]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SAML SSO akışı varsa: `SAMLResponse`/`SAMLRequest` (base64, çoğu zaman URL-encode; redirect-binding'de ayrıca DEFLATE) içeren `/acs`, `/saml/consume`, `/sso`, `/login/callback` endpoint'i.
- İpuçları: `Location` içinde `SAMLRequest=`, formda gizli `SAMLResponse` alanı, `<saml:Assertion>` / `<ds:Signature>` / `NameID` içeren XML, IdP-initiated login.
- SKIP: SSO OIDC/JWT tabanlıysa bu sınıf değil (→ JWT/OAuth playbook'u). Hiç SAML zarfı yoksa SKIP. XML parser'ın kendisi hedefse → [[vuln-xxe]].

## 2. İNSAN MUHAKEMESİ
- Geliştirici "IdP imzaladıysa içerik güvenlidir" varsaymış olabilir; ama imza yalnızca BİR `Reference URI`'yi korur. SP imzanın HANGİ elemanı koruduğunu, parser'ın HANGİ elemanı okuduğunu ayrı ayrı çözüyorsa — ikisini ayırabilirsem kazanırım.
- Klasik hatalar: (a) imza opsiyonel/yokken de kabul; (b) `Reference URI` ile parser'ın seçtiği assertion farklı (XSW); (c) `NameID` string karşılaştırması XML yorumuyla kesiliyor; (d) `Recipient`/`Audience`/`NotOnOrAfter` doğrulanmıyor.
- Asıl mesele: imza-gövde BAĞI. Bağ gevşekse, imzayı bozmadan okunan kimliği değiştiririm.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Geçerli bir SSO ile gel; gerçek `SAMLResponse`'u yakala (decode et), başarılı login'in set-cookie/redirect'ini ve `NameID`'yi not al. request_id sakla. İmzalı orijinali bozmadan ACS'e replay → yine login olmalı (kontrol noktası).
- **Tek prob (imza dışlama):** Response'tan `<ds:Signature>` bloğunu TAMAMEN sil, `NameID`'yi `admin@<hedef>` yap, yeniden encode et, `cyp_send_request` ile ACS'e gönder. SP login açıyor mu?
- **Tek prob (imzasız assertion eklemek / XSW):** Orijinal imzalı assertion'ı koru ama yeni, attacker `NameID`'li İKİNCİ bir assertion ekle ve onu parser'ın okuyacağı konuma (kök altına / mevcut imzalı assertion'ı `<Object>` veya sarmalayıcıya taşıyıp) yerleştir. İmza hâlâ orijinali "valid" sayar, parser benimkini okur.
- **Tek prob (yorum-enjeksiyonu):** `NameID`'yi `admin<!---->@<hedef>` yap. Bazı kütüphaneler text-node'u yorumda keser → imza `admin@<hedef>...` için geçerli kalır ama uygulama `admin` görür.
- Her probda decode→düzenle→encode→`cyp_send_request` zincirini canonicalization'ı bozmadan uygula (whitespace dikkat).

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Manipüle response BAŞKA kimlikle (özellikle admin/başka tenant) geçerli oturum açtı — set-cookie + korunan kaynağa erişim. Negatif kontrolde (rastgele bozma) reddedilirken bu spesifik manipülasyon kabul ediliyor.
- **Gürültü (aday DEĞİL):** "signature validation failed", "invalid SAML", `RequestDenied`, 4xx redirect-to-login. SP'nin doğru doğruladığının kanıtı. Salt 500 de değil. Kendi geçerli baseline'ının tekrar açılması da bulgu değil.

## 5. DOĞRULAMA KAPISI (kanıt)
- **İmza dışlama / imzasız kabul:** İmzasız + değiştirilmiş `NameID`'li response oturum açtı; aynı response'a tek byte imza eklenince fark etmiyor (yani imza hiç doğrulanmıyor). 2 farklı `NameID` ile farklı kullanıcı oturumu → sabit değil.
- **XSW:** İmzalı blok orijinal, okunan assertion attacker'ınki; korunan kaynağa attacker kimliğiyle erişim. request_id'lerle: baseline-login vs XSW-login vs negatif (sarmalama bozuk) reddi.
- **Yorum-enjeksiyonu:** `admin<!---->@x` ile `admin@x` kullanıcısının oturumu açıldı, düz `attacker<!---->@x` ile attacker oturumu → string kesme deterministik.
- Her iddia: orijinal response request_id + manipüle response request_id + açılan oturumun korunan-kaynak request_id'si.

## 6. VARYASYON / BYPASS (bloklanınca)
- **XSW varyantları:** assertion'ı imzalı kökün altına/kardeşine/`<Extensions>`/`<Object>` içine taşıma; `ID`/`Reference URI` çakıştırma (aynı `ID`'li iki eleman → parser ilkini, doğrulayıcı ikincisini); Response-imzalı vs Assertion-imzalı senaryolarını ayrı dene (8 klasik XSW pozisyonu).
- **Doğrulama eksenleri:** `Recipient`/`Destination`/`Audience`'ı kendi SP'ne ait olmayan değere çevir — reddetmiyorsa IdP-confusion/recipient bypass. `NotOnOrAfter`'ı geçmişe al → süre kontrolü var mı.
- **IdP confusion / key:** Kendi IdP'nle/self-signed key ile imzala; SP metadata'daki IdP cert'i pinlemiyorsa kabul eder (tam ATO). `KeyInfo` içine kendi cert'ini göm.
- **Encoding/binding:** redirect-binding ise DEFLATE+base64+URL-encode sırasını koru; POST-binding'de form alanı. XML-DSig transform'larıyla (`enveloped-signature`) oyna.
- **XXE pivotu:** Assertion gövdesi parser'a gidiyor → DOCTYPE/entity denemesi ayrı bir sınıf (→[[vuln-xxe]]).
- Her eksen bir hipotez; 3-5 XSW pozisyonu + dışlama + yorum denenip hiçbiri oturum açmıyorsa dürüstçe "imza-gövde bağı sağlam, SAML bypass yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Geçerli baseline response'un tekrar oturum açmasını "bypass" sanmak. Orijinali değil, MANİPÜLE edileni gönder; kimlik DEĞİŞMELİ.
- "signature validation failed" hatasını zafiyet sanmak — bu doğru reddetmedir, bulgu değil.
- Decode edilmiş XML'i locale'de düzenlerken whitespace/canonicalization'ı bozup imzayı kendin geçersiz kılıp "reddetti" demek — XSW olmadan bile imza zaten kırılır; canonical formu koru.
- Aynı kullanıcı kalırken oturum açılmasını "imza dışlandı" sanmak — kimlik değişmediyse kanıt yok; attacker/admin `NameID`'sine geçtiğini göster.
- DEFLATE/URL-encode katmanını atlayıp "kabul etmedi" demek — taşıma katmanını doğru kur, yoksa SP zaten parse edemez.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Manipüle (imzasız/XSW/yorum/yabancı-cert) response BAŞKA kimlikle oturum açtı + korunan kaynağa erişim + negatif kontrol (rastgele bozma) reddedildi.
- **Sinyal yok, kapat:** İmza dışlama reddediliyor, XSW pozisyonları + ID çakıştırma boş, yorum kesmiyor, recipient/audience/süre doğrulanıyor, yabancı cert reddediliyor.
- **Şüpheli, ilerle:** Bir varyant 500/tutarsız davranış üretiyor ama oturum açmadı → 1-2 XSW pozisyonu daha veya canonicalization'ı düzelt, sonra karar; istek bütçesini koru.

## ÖZET — 5 KURAL
1. Hedef imza-gövde BAĞI: imzayı bozmadan OKUNAN kimliği değiştirebiliyor musun?
2. Önce imza-dışlama probu; sonra XSW (imzalı blok dursun, ben başka assertion okutayım), sonra yorum-enjeksiyonu.
3. Kanıt = MANİPÜLE response ile BAŞKA/admin oturumu + negatif kontrol reddi; baseline'ın tekrarı kanıt değil.
4. "signature failed" / 4xx doğru reddetmedir — bulgu değil; kimlik değişmeden açılan oturum da değil.
5. Bloklanınca 8 XSW pozisyonu, ID çakıştırma, recipient/audience/süre, yabancı cert (IdP confusion) eksenlerini sırayla dene; boşsa kapat.
