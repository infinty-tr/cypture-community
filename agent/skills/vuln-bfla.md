---
name: vuln-bfla
description: >
  BFLA / fonksiyon düzeyi yetki (OWASP API #5): ayrıcalıklı bir İŞLEVİ/endpoint'i
  (admin aksiyonu, başka tenant operasyonu) düşük yetkili bir kimlikle çağırabiliyor
  muyuz? BOLA'dan farkı: nesne değil FONKSİYON. Ana karar: ayrıcalıklı işlem düşük
  yetkili kimlikle GERÇEKTEN gerçekleşti mi (durumu doğrula), yoksa 403 mü döndü?
---

# 🚪 BFLA — ayrıcalıklı bir İŞLEVİ düşük yetkiyle çağırabiliyorsan açıktır

> **Tek cümle:** BOLA "başkasının OBJESİNE eriştim" derken BFLA "yapmamam gereken İŞLEMİ yaptım" der; kanıt, düşük yetkili kimlikle ayrıcalıklı aksiyonun GERÇEKLEŞTİĞİNİN başka bir endpoint'ten doğrulanmasıdır.

İlişkili: [[access-control-reasoning]] [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[identity-acquisition]] [[chain-attack-builder]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Rol/yetki gerektiren bir İŞLEV/endpoint varsa: `/admin/*`, `/api/internal/*`, kullanıcı silme/banlama, rol atama, fatura iadesi, ayar değiştirme, başka tenant'ın operasyonu, "approve/publish/refund" gibi aksiyonlar.
- İpuçları: UI'da yalnız admin'e görünen butonlar; JS bundle'da gizli/dokümante olmayan admin route'ları; `Authorization`/rol kontrolünün sadece bir method veya bir endpoint'te olması; `role`/`is_admin` alanına bakan akışlar.
- SKIP: kararı veren şey hangi OBJEYE eriştiğinse (aynı işlev, farklı sahip) → [[vuln-idor]]. Fazla ALAN gönderme ise → [[vuln-mass-assignment]]. Burada işlevin KENDİSİNE erişim sorulur.

## 2. İNSAN MUHAKEMESİ
- Geliştirici ayrıcalıklı endpoint'i "zaten UI'da göstermiyorum" diye güvenli sanmış; sunucuda rol kontrolü yok ya da eksik.
- Yatay (tenant↔tenant: A-tenant kullanıcısı B-tenant işlemini çağırır) vs dikey (user→admin işlevi) ayır.
- Kaçırılan yer: kontrol sadece `GET /admin` sayfasında var ama `POST /admin/users/delete` çıplak; yetki sadece gateway'de var, mikroservis iç endpoint'i (`/internal/*`) açık; method override ile filtre atlanıyor; yeni eklenen endpoint role-gate'e bağlanmamış.

## 3. TEŞHİS PROB'U (önce baseline/iki-kimlik, sonra kademeli)
- **Kimlik edin:** Düşük yetkili `sessionId="low"` (normal user) ve mümkünse yüksek yetkili `sessionId="admin"` referans için (→ [[identity-acquisition]], [[engine-mcp-contract]] §3).
- **Fonksiyon keşfi:** Ayrıcalıklı endpoint'leri bul — admin oturumundaki istekler, JS route tablosu, swagger/openapi, `/admin`,`/internal`,`/manage`,`/api/v*/admin` tahminleri (kör değil, kaynaklı).
- **Baseline:** Admin ile ayrıcalıklı işlevi normal çağır (`cyp_send_request`, sessionId=admin) → 200 + işlem gerçekleşti; etkisini başka endpoint'ten gör. request_id sakla. **Negatif kontrol:** düşük yetkili kimlik BEKLENEN 403 olmalı.
- **İhlal probu (kademeli):**
  1. Düşük yetkili token ile aynı ayrıcalıklı isteği AYNEN gönder (sessionId=low) → 200 + işlem gerçekleşti mi?
  2. **Method ekseni:** GET korunuyor ama `POST/PUT/DELETE` çıplak mı? `X-HTTP-Method-Override: DELETE`.
  3. **Hidden/undocumented:** UI'da olmayan ama JS/swagger'da geçen admin endpoint'ini doğrudan çağır.
  4. **Tenant-yatay:** A-tenant kimliğiyle B-tenant'ın yönetim işlemini tetikle.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Düşük yetkili kimlikle ayrıcalıklı işlem GERÇEKLEŞTİ — durum başka endpoint'ten doğrulandı (kullanıcı silindi, rol atandı, ayar değişti, iade yapıldı).
- **Gürültü (aday DEĞİL):** 200 ama işlem aslında olmadı (no-op); 403/401/404 (kontrol çalışıyor); 200 + "yetkisiz" gövdesi; endpoint var ama yalnız admin oturumunda gerçek etki; soft-redirect login'e.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Etki doğrulaması zorunlu:** Düşük yetkili kimlikle ayrıcalıklı çağrı (req_AAAA) + AYRI bir okuma/durum isteğiyle işlemin GERÇEKLEŞTİĞİNİ gösteren kanıt (req_BBBB). "200 döndü" tek başına yetmez — banlanan kullanıcı gerçekten banlı mı, rol gerçekten değişti mi?
- **Negatif kontrol:** Aynı işlev admin ile baseline olarak çalışıyor (req_id), düşük yetkili kimlik AYNI sonucu üretiyor → yetki yok. Ters yönde: tamamen anonim/geçersiz token reddediliyor mu (yoksa auth hiç çalışmıyor olabilir, onu ayır).
- N≥2 tekrar, mümkünse geri-alınabilir/zararsız işlevle (test hesabı üzerinde). Baseline ↔ ihlal request_id eşleştir.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Method ekseni:** `GET↔POST↔PUT↔DELETE↔PATCH`, `X-HTTP-Method-Override`, `_method=DELETE`; bazı katman yalnız bir metodu korur.
- **Path ekseni:** `/admin/x` vs `/api/admin/x` vs `/internal/x` vs `/v2/admin/x`; path normalization (`/admin/../admin`, trailing slash, case, URL-encode `%2e`).
- **Header/rol ekseni:** `X-Forwarded-For`/`X-Original-URL`/`X-Rewrite-URL` ile gateway atlatma; `Role`/`X-Admin` header denemesi (sunucu güveniyor mu).
- **Content-Type ekseni:** JSON↔form; bazı yetki katmanı yalnız bir tipi denetler.
- **Tenant ekseni:** istekte `tenant_id`/`org_id` değiştir, başka tenant işlevini çağır. Her eksen bir hipotez; 3-5 denemede gerçek-etki sinyali yoksa dürüstçe "BFLA sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **200'ü işlem sanmak:** Endpoint 200 dönüp hiçbir şey yapmamış olabilir (no-op/echo). Durumu başka endpoint'ten DOĞRULA.
- **Endpoint varlığını yetki açığı sanmak:** `/admin` 200 döndü ≠ admin işlevi çalıştı; gerçek ayrıcalıklı etki şart.
- **Anonim 200'ü BFLA sanmak:** Eğer her şey (geçersiz token dahil) 200 ise auth hiç çalışmıyordur — bunu BFLA'dan ayır, ayrı raporla.
- **BOLA ile karıştırmak:** Sorun başka birinin OBJESİNE erişimse o IDOR'dur; BFLA işlevin kendisine erişimdir.
- **403'ü bypass sanmak:** Method/path varyantı denedin ama hâlâ etki yok → koruma çalışıyor.
- **Tek istekle iddia:** Etki ve negatif kontrol olmadan BFLA raporlama; geri-alınamaz yıkıcı işlemi prod'da TETİKLEME.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Düşük yetkili kimlikle ayrıcalıklı işlem gerçekleşti (etki ayrı endpoint'ten doğrulandı) + N tekrar + negatif kontrol (anonim/geçersiz reddedildi, admin baseline çalışıyor).
- **Sinyal yok, kapat:** Düşük yetkili istekler 403/401; 200'ler no-op; method/path/header/tenant eksenleri tükendi.
- **Şüpheli, ilerle:** 200 var ama gerçek etki belirsiz → durumu başka endpoint'ten doğrula, bir hedefli prob daha; bütçeyi kör endpoint brute'una harcama.

## ÖZET — 5 KURAL
1. BFLA fonksiyona erişimdir; obje sahipliği sorunuysa o [[vuln-idor]], fazla alan ise [[vuln-mass-assignment]].
2. Ayrıcalıklı endpoint'leri kaynaklı keşfet (admin trafiği/JS/swagger), kör brute değil.
3. Kanıt "200" değil; işlemin GERÇEKLEŞTİĞİNİN başka endpoint'ten doğrulanmasıdır.
4. Method/path/header/tenant/Content-Type eksenlerini dene; çoğu kontrol tek bir varyantı korur.
5. Her kanıt = düşük yetkili ihlal + etki doğrulama + negatif kontrol (admin baseline + anonim red) request_id'leri.
