---
name: vuln-graphql
description: >
  GraphQL Saldırıları sınıfı: hedefte bir GraphQL endpoint'i (/graphql vb.) varsa
  uygulanır. Introspection açıklığı, alan-bazlı yetki (BOLA/BFLA), batch/alias ile
  rate-limit atlama, derin iç içe sorgu (DoS) ve resolver injection alanlarını bulur.
  Ana karar: şema GERÇEKTEN sızdı / yetkisiz alan GERÇEKTEN okundu mu, yoksa her hatayı
  açık mı sandık?
---

# 🔺 GRAPHQL SALDIRILARI — bir GraphQL endpoint'i varsa introspection/yetki/batch eksenlerini sına

> **Tek cümle:** GraphQL tek uçtan çok işlevi açar; kanıt "endpoint cevap verdi" değil, introspection'ın ŞEMA döktüğü / yetkisiz bir alanın VERİ döndürdüğü / batch'in korumayı ATLADIĞIdır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[access-control-reasoning]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Hedefte bir GraphQL uç noktası varsa: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`; `Content-Type: application/json` ile `{"query":"..."}` gövdesi; GraphiQL/Playground/Apollo UI'si.
- İpuçları: cevapta `"data"`/`"errors"` zarfı; `__typename` çalışıyor; "Cannot query field ... Did you mean ...?" tarzı öneri mesajları.
- SKIP: saf REST/RPC ise. Yetki muhakemesi gerektiren her şeyde → [[access-control-reasoning]] ile düşün.

## 2. İNSAN MUHAKEMESİ
- GraphQL tek endpoint, çok resolver demek; yetki çoğu zaman resolver/alan düzeyinde uygulanmalı ama global sanılır. Geliştirici REST için koyduğu kontrolü alan bazında tekrarlamamış olabilir.
- Kaçırılan yer: introspection prod'da açık; alan/obje yetkisi resolver'da değil; rate-limit istek başına sayılır ama batch/alias tek istekte N işlem yapar; arg'lar alttaki DB/servise sanitize edilmeden gider (injection); mutation'lar query kadar sıkı yetkilenmez.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Bilinen geçerli bir sorgu (örn. `{ __typename }`) at; data zarfı, status, hata biçimini not et. request_id sakla.
- **Endpoint teyidi:** `GET`/`POST` her ikisini, `application/json` vs `application/graphql`, ve metot kısıtını gözle — bazı korumalar yalnız bir taşımayı kapatır.
- **Tek prob (ekseni seç, her seferinde TEK):**
  1. **Introspection:** `{__schema{types{name}}}` (kanonik minimal) → tipler listesi DÖNDÜ mü, yoksa "introspection disabled" mı? Kapalıysa `{__schema{queryType{name}}}` ile çift teyit.
  2. **Alan/obje yetkisi (BOLA):** düşük-yetkili token ile başka kullanıcının objesini iste: `{ user(id:"<diğer>"){ email } }` → veri döndü mü? [[access-control-reasoning]] kararını uygula.
  3. **Fonksiyon yetkisi (BFLA):** düşük-yetkili token ile admin-only mutation/query (`{ allUsers{ email } }`, `mutation{ deleteUser(id:..) }`) çağır → izin verildi mi?
  4. **Batch/alias:** tek istekte alias'larla aynı mutation'ı N kez (`a:login(...) b:login(...) ...`) → hepsi işlendi mi (rate-limit atlandı mı)?
- Her prob sonrası `"data"` ile `"errors"`'u AYIR: veri geldi mi yoksa sadece hata zarfı mı?
- **Cypture notu:** Sorguyu `{"query":"..."}` JSON gövdesiyle `cyp_send_request` ile yolla; BOLA testinde iki farklı `Authorization` token'ı ile aynı sorguyu çalıştır ve iki request_id'yi karşılaştır. **Ekonomi:** batch/alias'ı TEK istekte çoklu alias olarak gönder — N ayrı istek atma, GraphQL'in tam gücü budur. [[engine-mcp-contract]] [[request-economy]].

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Introspection gerçek şema (tip/alan adları) döktü; VEYA yetkisiz token başka kullanıcının ALAN VERİSİNİ okudu / admin mutation'ı işletti; VEYA batch/alias tek istekte N başarılı işlem yaptı (rate-limit/koruma atlandı).
- **Gürültü (aday DEĞİL):** Her `"errors"` cevabı (çoğu yetki/validation'dır, açık değil); "field suggestions" tek başına şema dökümü değil; introspection KAPALI iken jenerik hata; 200 + `"data":null`.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Introspection:** `__schema` cevabı gerçek tip/alan adları içeriyor (jenerik hata değil) — tek request_id yeterli ama tekrar et.
- **BOLA/BFLA:** Aynı alan/mutation, **yetkili kimlikle** (sahibi/admin) çalışır; **yetkisiz kimlikle** de AYNI veriyi döndürür / işlemi yaparsa açık. İki request_id (yetkili vs yetkisiz) + negatif kontrol (geçersiz id/token → erişim yok). [[access-control-reasoning]] kapısından geçir.
- **Field-level authz farkı:** aynı objenin sıradan alanları döner ama hassas alan (`email`/`ssn`/`role`) yetkisize de dönüyorsa, alan-bazlı yetki yok — alan-alan karşılaştır.
- **Batch:** N işlemden M>1 başarılı, oysa REST muadili 1 istekte 1 ile sınırlı; tek request_id'de çoklu başarı + (mümkünse) brute etkisinin ölçülebilir kanıtı (örn. farklı OTP/parola denemeleri tek istekte).
- N tekrar; baseline ↔ tetikleyici request_id eşleştir.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Introspection ekseni:** kapalıysa alan-öneri (field suggestion) ile şema çıkarımı; `__type(name:"User")` ile tek tip yokla; GET/POST taşıma farkı; `__schema` filtresi yalnız POST'ta ise GET dene.
- **Yetki ekseni:** mutation vs query ayrı yetkilenebilir; **nested ilişkilerden dolaylı erişim** (`{ me{ orders{ user{ email } } } }` ile başkasının email'i); aynı objeye farklı resolver'dan ulaşma; alias ile aynı objeyi farklı arg'larla iste.
- **Batch ekseni:** array batching (`[{q1},{q2}]`) vs alias batching; her ikisi de tek istekte N işlem → rate-limit/CAPTCHA'yı atlatabilir. Auth brute'unu tek alias-istekle ölç (ekonomi).
- **Mutation abuse ekseni:** yetki/iş-mantığı atlayan mutation (state-change, fiyat/rol/quota), `__typename` ile gizli mutation keşfi, mutation'ın query'den daha gevşek yetkilenmesi.
- **Injection ekseni:** arg değerlerine SQL/NoSQL/komut payload'ı — resolver alttaki DB/servise sanitize etmeden geçirebilir; sinyal varsa ilgili vuln skill'ine geç ([[access-control-reasoning]] yetki tarafı için).
- **DoS ekseni (DİKKAT, HAFİF):** sadece SIĞ bir iç içe sorguyla derinlik/karmaşıklık/cost limiti VAR MI diye yokla; circular fragment veya `first:99999` ile servisi YORMA. Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Introspection kapalıyı açık sanmak:** "errors" veya boş cevabı şema dökümü saymak. Gerçek tip/alan adları gelmedikçe introspection açık DEĞİL.
- **Her hatayı açık sanmak:** `"errors"` çoğunlukla yetki reddi/validation'dır — bu KORUMANIN ÇALIŞTIĞInı gösterir, açık değil.
- **Field suggestion'ı tam şema sanmak:** öneri mesajı ipucudur, kanıtlı şema dökümü değildir.
- **`data:null`'ı erişim sanmak:** null veri = erişim yok; sadece veri DÖNDÜYSE BOLA.
- **Derin sorgu/cost'u test ederken servisi yormak:** DoS'u kanıtlamak için saldırı yapma; varlığını (limit yokluğunu) hafif yokla.
- **Batch'i tek başarı ile açık sanmak:** alias döndü ama hepsi reddedildiyse koruma çalışıyor; atlama ancak N işlemin BAŞARILI olmasıyla kanıtlanır.
- **GraphiQL/Playground varlığını açık sanmak:** UI açık ama introspection sunucuda kapalı olabilir; gerçek `__schema` cevabını gör.
- **N ayrı istek atıp ekonomi yakmak:** batch/alias varken brute'u N ayrı istekle yapmak GraphQL'in özelliğini boşa harcar.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** introspection şema döktü / yetkisiz alan veri döndü / admin mutation işledi (access-control kapısından geçti) / batch korumayı atladı — + N tekrar + negatif kontrol.
- **Sinyal yok, kapat:** introspection kapalı, yetkisiz istekler reddediliyor, batch limitleniyor, cost-limit var; eksenler tükendi.
- **Şüpheli, ilerle:** field suggestion ile kısmi şema sızıyor ama tam erişim belirsiz → hedefli bir yetki/nested probu daha, sonra karar.

## ÖZET — 5 KURAL
1. "errors" cevabı çoğu zaman KORUMADIR; her hatayı açık sanma.
2. Introspection ancak gerçek tip/alan adları dökerse açıktır; boş/hata = kapalı.
3. BOLA/BFLA'yı yetkili-vs-yetkisiz iki kimlikle, alan-alan karşılaştırarak kanıtla; [[access-control-reasoning]] kapısından geçir.
4. Batch/alias'ı TEK istekte çoklu BAŞARI ile kanıtla (ekonomi); tek cevap dönmesi yetmez.
5. Derin/cost-sorgu DoS'unu hafif yokla, ASLA servisi yorma; her kanıt = baseline + tetikleyici request_id.
