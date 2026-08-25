---
name: vuln-ldap-injection
description: >
  Kullanıcı girdisi bir LDAP/AD filtresine (login, dizin arama) string olarak
  giriyorsa uygulanır. `*`, `)(`, `&`, `|` ile filtre mantığını kırıp auth bypass
  veya attribute exfil dener. Ana karar: girdi filtre AĞACINI mı değiştiriyor,
  yoksa sadece "kullanıcı yok" mu dönüyor?
---

# 🗂️ LDAP INJECTION — girdi dizin filtresinin mantığını değiştiriyorsa açıktır

> **Tek cümle:** Girdiyi veri sanan LDAP filtresine `*`/`)(` enjekte edip mantığı kontrolüne al; kanıt, kontrollü iki istek arasındaki ÖLÇÜLEBİLİR auth/sonuç farkıdır.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[chain-attack-builder]] [[data-flow-and-mental-model]] [[request-economy]] [[vuln-sqli]] [[vuln-nosqli]] [[attacker-mindset-and-persistence]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi bir LDAP/AD filtresine gidiyorsa: login (`(uid=<girdi>)`), dizin/çalışan araması, grup üyeliği kontrolü, adres defteri, "kullanıcı adı müsait mi" kontrolü.
- İpuçları: kurumsal SSO/AD entegrasyonu, e-posta/username ile login, `cn`/`uid`/`sAMAccountName` görünen alanlar, `*` gönderince arama sonucunun değişmesi, parantez gönderince hata/garip davranış.
- SKIP: girdi RDBMS sorgusuna gidiyorsa → [[vuln-sqli]]; doküman store'a → [[vuln-nosqli]]. Girdi hiç dizine ulaşmıyorsa SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici filtreyi string concatenation ile kurmuş olabilir: `(uid=<girdi>)` veya login için `(&(uid=<girdi>)(password=<girdi>))`. Escape (`\2a`, `\28`, `\29`) yapsaydı kapalı olurdu.
- Mantık: `*` LDAP'ta wildcard → `(uid=*)` "herhangi biri" demek; `)(` ile mevcut filtre erken kapanır ve yeni koşul enjekte edilir; `|` OR'a, `&` AND'e çevirir.
- Kaçırılan yer: parolayı filtreye gömen ("LDAP search-then-bind" yerine doğrudan filtre eşleştiren) login, ya da arama kutusunda `*` ve parantezi filtrelemeyen kod.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** girdiyi değiştirmeden gönder (`cyp_send_request`); status + body uzunluğu + sonuç sayısı / login sonucunu not et. request_id sakla. Negatif kontrol: var olmayan bir kullanıcı → "bulunamadı".
- **Tek prob (kademeli):**
  1. Tek `*` ekle → arama "hepsini" mi döndü (baseline'dan çok daha fazla sonuç)? Login'de `*` parola yerine girince giriş oldu mu?
  2. Yapı kırma: `)` ekle → filtre syntax kırıldı mı (hata / farklı body)? `\29` ile escape'lenmiş `)` baseline'a dönüyor mu (kırılmanın paranteze bağlı olduğunu gösterir).
  3. Auth bypass: kullanıcı alanına `*)(uid=*))(|(uid=*`, ya da `admin)(&)` / `admin*` dene → giriş/sonuç mantıkla değişti mi.
  4. Blind boolean: `<gerçek-uid>)(&(uid=<gerçek-uid>)(description=A*` vs `...(description=Z*` → var/yok deterministik farkı veriyorsa attribute substring exfil mümkün.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `*` baseline'dan belirgin daha fazla sonuç getiriyor; `)` kırıyor + `\29` düzeltiyor; `*)(uid=*))(|(uid=*` ile login başarılı; boolean substring çifti (`A*` var / `Z*` yok) deterministik tekrarlanıyor.
- **Gürültü (aday DEĞİL):** her girdide dönen jenerik "kullanıcı bulunamadı"; `*`'ın text olarak aranıp 0 sonuç vermesi (escape edilmiş = kapalı); tek seferlik garip cevap; WAF blok sayfası.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Filter injection:** `*` → çok-sonuç, normal → tek/sıfır sonuç. İki request_id ile göster.
- **Auth bypass:** `*)(uid=*))(|(uid=*` (veya `*`) → kimliği doğrulanmış oturum/yönlendirme; negatif kontrol: aynı akış meşru-yanlış parolada reddediyor. Token/Set-Cookie/redirect farkını request_id'lerle göster.
- **Blind boolean/exfil:** TRUE substring = içerik A, FALSE = içerik B; en az 2-3 tekrar deterministik. Karakter karakter genişleterek attribute (örn. `userPassword` hash, e-posta) çıkarılabildiğini somut diziyle göster.
- Her iddia için baseline request_id + tetikleyici request_id zorunlu.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Operatör ekseni:** `&` (AND), `|` (OR), `!` (NOT), iç içe `(&(...)(...))`, `(|(...)(...))`.
- **Escape/encoding:** ham `*`/`(`/`)` tıkalıysa URL-encode (`%2a`, `%28`, `%29`), çift-encode, null `%00` ile filtre kuyruğunu kesme (`admin)(uid=*))%00`).
- **Sink/metot:** JSON body / header / arama parametresi; GET tıkalıysa POST; login alanı tıkalıysa parola alanına enjekte.
- **Attribute ekseni:** `cn`, `uid`, `sAMAccountName`, `mail`, `memberOf`, `description`, `userPassword` — hangi attribute filtrede kullanılıyorsa onu hedefle.
- Her eksen bir hipotez; 3-5 denemede sinyal yoksa dürüstçe "LDAPi sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **`*`'ı her zaman wildcard sanmak:** Escape edilmişse `*` literal aranır, 0 sonuç döner — bu açık DEĞİL. Baseline'a göre sonuç ARTIŞI şart.
- **Jenerik hatayı injection sanmak:** "kullanıcı bulunamadı" her yanlış girdide döner; mantık farkı değildir. `\29` ile düzelmeyen kırılma LDAPi değil.
- **Tek geniş sonucu kanıt sanmak:** Bazı aramalar zaten çok sonuç döndürür; baseline ile karşılaştır, negatif kontrol al.
- **SQLi ile karıştırmak:** Tırnak (`'`) LDAP'ta özel değildir; LDAP sinyali `*`/`)(`/parantez dengesidir. Yanlış sınıf seçme.
- **WAF blok sayfasını "farklı cevap" sanmak:** WAF her şüpheli inputa aynı sayfayı verir; mantık farkı değil.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** filtre mantığı değişti (çok-sonuç / auth bypass / boolean exfil) + N tekrar + negatif kontrol + escape ile düzelme gösterildi.
- **Sinyal yok, kapat:** `*`, parantez, operatör, encoding eksenleri denendi; hiçbiri deterministik fark üretmedi (girdi escape ediliyor).
- **Şüpheli, ilerle:** `*` sonuç sayısını oynatıyor ama auth bypass/exfil zinciri eksik → tek hedefli prob daha (boolean substring), sonra karar; istek bütçesini boşa harcama.

## ÖZET — 5 KURAL
1. Önce baseline + negatif kontrol al, sonra TEK prob gönder — kör parantez püskürtme yok.
2. `*` baseline'dan FAZLA sonuç getirdiyse sinyal; `)` kırdıysa `\29` ile düzeldiğini kanıtla.
3. Auth bypass'ı `*)(uid=*))(|(uid=*` ile gerçek oturum + negatif kontrol üzerinden göster.
4. Blind exfil'i TRUE/FALSE substring çiftiyle deterministik tekrarla kanıtla.
5. Her kanıt = baseline request_id + tetikleyici request_id; tırnağı LDAPi sinyali sanma.
