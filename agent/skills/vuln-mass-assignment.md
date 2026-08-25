---
name: vuln-mass-assignment
description: >
  Mass Assignment / autobinding (OWASP API #3): bir yazma isteğine objenin
  ayrıcalıklı alanlarını (role, is_admin, balance, owner_id, verified) eklersen
  framework bunları körü körüne bağlar mı? Ana karar: gönderilen yetkisiz alan
  KALICI olarak değişti mi (durumu doğrula), yoksa sessizce yok mu sayıldı?
---

# 🧬 MASS ASSIGNMENT — yazma isteğine ayrıcalıklı alan ekleyince obje onu kabul ediyorsa açıktır

> **Tek cümle:** Update/create isteğine göndermemen gereken alanı ekle; kanıt "200 döndü" değil, o alanın objede KALICI değiştiğinin başka bir istekten doğrulanmasıdır.

İlişkili: [[access-control-reasoning]] [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[identity-acquisition]] [[chain-attack-builder]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Bir obje oluşturan/güncelleyen yazma isteği varsa: `POST/PUT/PATCH /users/me`, `/register`, `/orders`, `/profile`, `/settings`; gövdesi JSON veya form ve sunucu bunu bir model'e bind ediyorsa.
- İpuçları: GET yanıtında istekte göndermediğin alanlar (`role`, `is_admin`, `verified`, `balance`, `owner_id`, `tenant_id`, `status`); ORM kullanımı (Rails/Spring/Django/Mongoose); `create(req.body)` / `update_attributes(params)` kalıbı.
- SKIP: yetki başka bir FONKSİYONA erişimle ilgiliyse → [[vuln-bfla]]; başka birinin objesini referanslamakla ilgiliyse → [[vuln-idor]]. Burada SENİN objen ama YETKİSİZ ALAN.

## 2. İNSAN MUHAKEMESİ
- Geliştirici tüm gövdeyi tek seferde model'e bağlamış (`User.update(params)`), allowlist (strong params / DTO) tanımlamamış. İstemcinin gönderdiği her alan kolona yazılıyor.
- Framework'e göre kalıp:
  - **Rails:** strong params unutulmuş → `params.permit!` veya doğrudan `update(params[:user])`.
  - **Spring:** `@ModelAttribute` binding'i kısıtlanmamış (no `@InitBinder`/allowlist), DTO yerine entity'ye bind.
  - **Express/Mongoose:** `Model.create(req.body)` / `findByIdAndUpdate(id, req.body)` — schema strict değil veya ekstra alan geçer.
  - **Django:** `ModelForm`/serializer `fields = '__all__'`, `setattr` döngüsü.
- Kaçırılan yer: nested obje (`{"user":{"role":"admin"}}`), array trick, alanın gizli/dokümante olmaması.

## 3. TEŞHİS PROB'U (önce baseline/iki-kimlik, sonra kademeli)
- **Alan keşfi:** Aynı objenin GET yanıtındaki TÜM alanları topla; farklı rolün (admin) yanıtındaki ekstra alanları, JS'deki model/DTO tanımlarını, hata mesajlarını kaynak al → ayrıcalıklı alan adları aday listesi.
- **Baseline:** Normal update isteğini değiştirmeden gönder (`cyp_send_request`, sessionId=A) → 200; sonra GET ile objeyi tekrar çek, mevcut `role`/`balance`/`verified` değerini not et. request_id'leri sakla. (Mümkünse admin objesini B olarak gözlemle — [[identity-acquisition]].)
- **Tek prob (kademeli):**
  1. Düz alan ekle: `{"email":"...","role":"admin"}` veya `is_admin:true`, `balance:99999`, `verified:true`, `owner_id:<B>`.
  2. **Doğrula:** Objeyi yeniden çek/relogin → alan GERÇEKTEN değişti mi? (200 yetmez.)
  3. **Nested injection:** `{"profile":{"isAdmin":true}}`, `{"user":{"role":"admin"}}` — düz alan filtreliyse iç içe dene.
  4. **Tip/array trick:** `role[]=admin`, `{"roles":["admin"]}`, string yerine bool/int, `__proto__`/`constructor` (proto pollution sınırında, → [[chain-attack-builder]]).

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Eklenen ayrıcalıklı alan objede KALICI değişti (sonraki GET/relogin'de görünüyor) ve gerçek bir ayrıcalık kazandırıyor (admin yetkisi, bakiye, başka tenant).
- **Gürültü (aday DEĞİL):** 200 ama alan değişmemiş (sessizce strip edildi); yanıtta echo edilmiş ama persist edilmemiş; alan zaten yazılabilir/zararsız (kozmetik); validation hatası (kontrol çalışıyor).

## 5. DOĞRULAMA KAPISI (kanıt)
- **Persist kanıtı zorunlu:** Yazma isteği (req_AAAA, ayrıcalıklı alan içeren) + AYRI bir okuma isteği (req_BBBB, GET ile değişmiş değeri gösteren). Yanıttaki echo yetmez — kalıcılık şart.
- **Etki kanıtı:** Değişen alan gerçek ayrıcalık verdi mi? (örn. `role:admin` sonrası admin-only endpoint artık erişilebilir → [[vuln-bfla]] kapısı). Negatif kontrol: alanı eklemeden aynı istek bu ayrıcalığı vermiyor.
- N≥2 tekrar; her seferinde objeyi geri çekerek deterministik doğrula. Baseline (alan eski değeri) ↔ ihlal (yeni değer) request_id eşleştir.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Format ekseni:** JSON kapalıysa form-urlencoded (`role=admin`), `multipart`, query string'e taşı; `Content-Type` değiştir.
- **Nesting ekseni:** düz alan strip ediliyorsa nested obje, dizi içinde obje, dotted notation (`user.role=admin`).
- **Alan adı ekseni:** `role` / `roles` / `is_admin` / `isAdmin` / `admin` / `user_role` / `account_type` / `grade` — naming convention'ı GET yanıtından/JS'den çıkar.
- **Tip ekseni:** bool↔int↔string, array vs scalar, null injection.
- **Endpoint ekseni:** aynı obje farklı endpoint'ten (register vs update vs admin-import) farklı binding'e sahip olabilir. Her eksen bir hipotez; 3-5 denemede persist eden sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Echo'yu persist sanmak:** Yanıt gönderdiğin alanı geri yansıtabilir ama DB'ye yazmamıştır. Mutlaka ayrı GET ile doğrula.
- **Zararsız alanı ayrıcalık sanmak:** `display_name`/`theme` değişti diye mass assignment yok — alan gerçek bir GÜVENLİK SINIRINI (admin/balance/owner) geçmeli.
- **200'ü kabul sanmak:** Çoğu API bilinmeyen alanı sessizce yok sayar; 200 = işlendi DEĞİL.
- **Zaten yazılabilir alanı bulgu sanmak:** Kullanıcının kendi adını değiştirmesi normal; ayrıcalık yükselişi yoksa bulgu yok.
- **Validation hatasını bypass sanmak:** 400/422 = koruma çalışıyor.
- **Tek istekle iddia:** Persist + etki doğrulaması olmadan mass assignment raporlama.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Ayrıcalıklı alan KALICI değişti (ayrı GET'le doğrulandı) + gerçek ayrıcalık etkisi + N tekrar + negatif kontrol (alansız istek etkisiz).
- **Sinyal yok, kapat:** Tüm alanlar strip ediliyor / sadece echo / validation reddediyor; format/nesting/alan-adı/tip eksenleri tükendi.
- **Şüpheli, ilerle:** Yanıtta alan görünüyor ama persist belirsiz → ayrı GET ile doğrula, bir prob daha; bütçeyi tahmin alan adlarına savurma.

## ÖZET — 5 KURAL
1. Önce GET yanıtı/JS'den ayrıcalıklı alan adlarını çıkar, sonra ekle — kör alan püskürtme değil.
2. Kanıt "200/echo" değil; alanın AYRI bir GET'te KALICI değiştiğidir.
3. Etki göster: değişen alan gerçek ayrıcalık (admin/balance/owner/tenant) kazandırmalı.
4. Düz alan filtreliyse nested obje / array / tip oyununu dene; framework kalıbını hesaba kat.
5. Her kanıt = baseline (eski değer) + ihlal (yeni değer) + etki + negatif kontrol request_id'leri.
