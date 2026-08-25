---
name: vuln-idor
description: >
  IDOR / BOLA (nesne düzeyi yetki): bir isteğin parametresi başka bir kullanıcının/
  tenant'ın objesine işaret ediyorsa uygulanır. Önce sahiplik modelini çıkar, sonra
  İKİ kimlikle (UserA↔UserB) sınırı ihlal et. Ana karar: yetkisiz kimlik başka
  birinin objesini GERÇEKTEN okudu/değiştirdi mi, yoksa 403/boş mu döndü?
---

# 🔑 IDOR / BOLA — bir objeye, sahibi olmadığın halde eriştiğinde açıktır

> **Tek cümle:** Önce "bu obje kime ait" modelini çıkar, sonra A'nın oturumuyla B'nin objesini iste; kanıt, yetkili-vs-yetkisiz iki istek arasındaki ÖLÇÜLEBİLİR yetki sapmasıdır — kör ID artırma değil.

İlişkili: [[access-control-reasoning]] [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[identity-acquisition]] [[chain-attack-builder]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- İstek, bir objeyi DOĞRUDAN referansla seçiyorsa: `/api/orders/123`, `?user_id=42`, `{"file_id":"..."}`, `/documents/<uuid>`, path/query/body/header/cookie içinde nesne kimliği.
- İpuçları: yanıtta `id`/`owner_id`/`account_id` alanları; URL'de sıralı sayı; "kendi profilini gör" akışı; başka kullanıcının verisini taşıyan komşu/üst/alt objeler (sipariş→kalem, hesap→fatura).
- SKIP: referans bir FONKSİYONA/endpoint'e erişim kararıysa (nesne değil işlev) → [[vuln-bfla]]. Obje gerçekten public ise (login gerektirmeyen, herkese açık içerik) IDOR yok.

## 2. İNSAN MUHAKEMESİ
- Geliştirici "id ile objeyi çek" yazmış ama "bu id çağıran kullanıcıya ait mi?" kontrolünü unutmuş: `Order.find(params[:id])` var, `.where(user: current_user)` yok.
- Mantık: kimlik doğrulama (authentication) var ama nesne düzeyi yetki (authorization) yok — token geçerli, ama o token'ın O objeye hakkı sorulmuyor.
- Kaçırılan yer: yetki sadece UI'da gizleniyor; sahiplik kontrolü liste endpoint'inde var ama detay/güncelleme endpoint'inde yok; "tahmin edilemez UUID güvenliktir" varsayımı (oysa UUID başka yerden sızıyor).
- Yatay (UserA↔UserB, aynı rol) vs dikey (user→admin objesi) ayır; çoğu IDOR yataydır.

## 3. TEŞHİS PROB'U (önce baseline/iki-kimlik, sonra kademeli)
- **Kimlik edin:** İki gerçek oturum aç — `sessionId="A"`, `sessionId="B"` (→ [[identity-acquisition]], [[engine-mcp-contract]] §3). Cookie/token karışmaz.
- **Sahiplik baseline'ı:** A olarak A'nın kendi objesini al (`cyp_send_request`, sessionId=A) → 200 + A'nın verisi, objenin ID/formatını ve dönen alanları not et. B olarak B'nin objesini al → 200. İki request_id sakla. **Negatif kontrol burada doğar:** A'nın B'nin objesine erişimi BEKLENEN 403/404 olmalı.
- **İhlal probu (kademeli):**
  1. **Read IDOR:** A token'ı ile B'nin ID'sini iste (sessionId=A, ama path/param B'nin objesi) → 200 + B'NİN verisi mi döndü?
  2. **ID formatını çöz, kör artırma:** sıralı sayı (`123→124`) birkaç komşu; UUID v4 enum etme, ID'yi response/JS/log/başka endpoint'ten SIZDIR; MongoID/hashid/base64 → `cyp_encode_decode` ile decode et, iç yapıyı anla.
  3. **Write IDOR:** sadece GET değil — `PUT`/`PATCH`/`DELETE` ile B'nin objesini değiştir/sil dene; durumu B oturumundan doğrula.
  4. **Sibling/parent:** üst objeden alt objeye sız (`/accounts/A/invoices/<B'ninki>`), nested ilişki üzerinden dolaylı eriş.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** A'nın oturumuyla B'nin objesi 200 + B'NİN GERÇEK verisi (A'nın baseline'ından farklı, B'nin baseline'ıyla aynı); VEYA yazma isteği sonrası B'nin objesi B oturumunda gerçekten değişti.
- **Gürültü (aday DEĞİL):** 200 ama boş/filtrelenmiş body (erişim yok, sadece zarf); soft-404 (her id 200 + "bulunamadı"); A ve B aynı veriyi görüyor çünkü obje PUBLIC; 403/404 (kontrol çalışıyor); WAF/generic redirect.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Read:** Yetkili kimlik (B, sahibi) → 200 + X verisi (req_AAAA). Yetkisiz kimlik (A) → AYNI X verisini döndürdü (req_BBBB). Negatif kontrol: geçersiz/var olmayan id → erişim yok. Dönen veri A'nın kendi verisi DEĞİL, B'ye ait olmalı (alan değerleriyle eşleştir).
- **Write:** A, B'nin objesini değiştirdi → değişiklik B'nin oturumundan okunduğunda görünüyor (yazma req_id + B'nin doğrulama req_id).
- N≥2 tekrar, farklı obje çiftleriyle tutarlı. Her iddia = baseline request_id + ihlal request_id; "200 döndü" tek başına kanıt değil, DÖNEN VERİNİN SAHİBİ kanıttır.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Ref formatı ekseni:** numeric, UUID, MongoObjectId, hashid, base64/base64url, JWT içi `sub` — decode et, başka yerden sızdır (kör enum YASAK, → [[chain-attack-builder]]).
- **Konum ekseni:** id'yi path'ten query'ye, body'ye, header'a (`X-User-Id`), cookie'ye taşı; bazı kontrol katmanı yalnız bir konumu denetler.
- **Metot/Content-Type ekseni:** GET kapalıysa POST; `_method`/`X-HTTP-Method-Override`; JSON↔form arası taşı.
- **Parametre kirletme:** `id=A&id=B` (HPP), array `id[]=A&id[]=B`, wrapped `{"id":["A","B"]}` — sunucu hangisini yetkilendirip hangisini kullanıyor?
- **Sibling/wildcard:** `*`, `0`, `me`, negatif id, `id=A.B` gibi composite. Her eksen bir hipotez; 3-5 hedefli denemede sinyal yoksa dürüstçe "IDOR sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **200'ü erişim sanmak:** Boş/filtrelenmiş gövdeli 200 erişim değildir. Dönen veride B'ye ait gerçek alanlar OLMALI.
- **Soft-404:** Uygulama var olmayan id'ye 200 + "kayıt yok" döndürür — bu IDOR değil. Geçerli komşu objeyle karşılaştır.
- **Public objeyi IDOR sanmak:** A ve B aynı veriyi görüyorsa, obje zaten herkese açıksa yetki sınırı yok demektir.
- **Kendi verisini başkasının sanmak:** Dönen veri aslında A'nın kendi objesi (id eşlemesi sapmış) — alan değerleriyle B'ye ait olduğunu DOĞRULA.
- **Yazmada 200'ü değişiklik sanmak:** PUT 200 döndü ama obje değişmedi olabilir; B oturumundan tekrar oku.
- **Tek kimlikle "tahmin" yapmak:** İkinci gerçek kimlik olmadan IDOR iddia etme; baseline 403 negatif kontrolü şart.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** A, B'nin objesini okudu/değiştirdi (B'nin gerçek verisiyle eşleşti) + N tekrar + negatif kontrol (geçersiz id reddedildi, baseline B-sahibi 200).
- **Sinyal yok, kapat:** Yetkisiz istekler 403/404; dönen 200'ler boş/public/soft-404; ref formatı/konum/metot eksenleri tükendi.
- **Şüpheli, ilerle:** 200 var ama dönen verinin sahibi belirsiz → alanları B'nin baseline'ıyla eşleştir, bir hedefli prob daha; istek bütçesini kör enuma harcama.

## ÖZET — 5 KURAL
1. Önce sahiplik modelini çıkar (obje kime ait, sınır nerede), sonra iki kimlikle ihlal et.
2. Kanıt "200" değil; A'nın oturumuyla dönen verinin B'ye AİT olmasıdır — alan değerleriyle eşleştir.
3. ID formatını çöz; UUID/hashid ise enum etme, başka yerden sızdır.
4. Sadece okuma değil yazma/silme ve sibling/parent objeleri de dene.
5. Her kanıt = baseline (sahibi 200) request_id + ihlal request_id + negatif kontrol (geçersiz id reddedildi).
