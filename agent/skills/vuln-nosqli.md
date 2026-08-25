---
name: vuln-nosqli
description: >
  NoSQL Injection sınıfı: girdi bir doküman-DB sorgusuna (özellikle MongoDB,
  CouchDB) gidiyorsa uygulanır. Sorgu operatörü ($ne/$gt/$regex/$where) enjekte
  edip sonuç kümesini veya auth davranışını değiştirebiliyor muyuz onu bulur.
  Ana karar: operatör girdiyi VERİDEN OPERATÖRE çevirdi mi?
---

# 🍃 NOSQL INJECTION — string beklenen yere operatör objesi geçirebiliyorsan açıktır

> **Tek cümle:** Backend girdiyi "değer" sanıyor; sen onu "$operatör"e çevirebiliyorsan sorgu mantığını ele geçirdin — kanıt, operatörlü vs operatörsüz davranış farkı.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-sqli]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi MongoDB / CouchDB / doküman-store sorgusuna gidiyorsa: login, arama, filtre, `find({...})` tabanlı uçlar.
- Güçlü ipuçları: JSON gövdeli API'lar, `username`/`password` JSON auth, Express+Mongo (Mongoose) stack, `qs`/`body-parser extended` ile parse edilen `param[$ne]=` formatı, `_design`/`_view` (Couch).
- SKIP: girdi klasik RDBMS'e gidiyorsa → [[vuln-sqli]]. Operatör hiçbir biçimde parse edilmiyorsa (katı şema/`String()` cast/Mongoose typed schema) SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici `db.users.find({user: req.body.user})` yazıp gövdeyi olduğu gibi geçmiş olabilir. `req.body.user` bir obje (`{"$ne":null}`) olursa Mongo bunu OPERATÖR olarak yorumlar — string değil.
- `qs`/Express `extended:true` parse `user[$ne]=` query string'ini de objeye çevirir — JSON şart değil; form-urlencoded bracket notasyonu da çalışır.
- Kaçırılan yer: girdiyi `String(...)`'e cast etmemek, tip kontrolü yapmamak, kullanıcı objesini doğrudan filtreye koymak.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** normal geçerli istek (doğru/yanlış kimlik), status + body + sonuç sayısını not et. request_id sakla.
- **Tek prob (taşıma ekseni — operatör hangi biçimde parse ediliyor):**
  1. **JSON gövde:** `{"username":"admin","password":{"$ne":null}}` → auth davranışı değişti mi (bypass / farklı cevap)?
  2. **Query-string:** `param[$ne]=x` veya `param[$gt]=` → sonuç kümesi büyüdü/değişti mi?
  3. **Form-urlencoded:** `param[$ne]=` bracket notasyonu (Content-Type `application/x-www-form-urlencoded`).
  4. **Karşıtlık probu:** `[$ne]` (her şey eşleşir) vs `[$gt]=zzzz` (hiçbiri eşleşmez) → sonuç kümesi mantıkla zıt yönde değişiyor mu?

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `{"$ne":null}` ile auth bypass / oturum açılması; `[$ne]` vs `[$gt]` arasında sonuç kümesi deterministik fark; operatörle dönen kayıt sayısının baseline'dan ölçülebilir sapması; `$where`/`$regex` ile boolean/time davranış farkı.
- **Gürültü (aday DEĞİL):** her JSON gövdeye dönen 200; operatörle de operatörsüzle de AYNI cevap; "JSON kabul edildi" gözlemi tek başına; parse hatası (400/500).

## 5. DOĞRULAMA KAPISI (kanıt)
- **Auth bypass:** `{"$ne":null}` ile yetkili cevap/oturum, normal yanlış parola ile RED — iki request_id ile göster, 2-3 tekrar deterministik.
- **Operatör etkisi:** `[$ne]` = geniş sonuç vs `[$gt]=<yüksek>` = boş sonuç; fark operatöre bağlı, sabit girdiye değil.
- **Negatif kontrol:** aynı alana operatörü düz string olarak (`"$ne"` literal değer) geçir → etki kaybolmalı; kaybolmuyorsa fark başka sebepten.
- **Blind boolean/time:** veri dönmüyorsa `$regex` ile char-char boolean oracle (`{"$regex":"^a"}` vs `^z`); MongoDB `$where:"sleep(5000)"` ile time (DİKKAT: server-side JS açıksa, hedefi yorma — kısa süre, negatif kontrol `sleep(0)`).

## 6. VARYASYON / BYPASS (bloklanınca) — operatör & motor özellikleri
- **Format/taşıma ekseni:** JSON body ↔ query-string `param[$ne]=` ↔ form-urlencoded `param[$ne]`. Content-Type `application/json` bloklanırsa form bracket notasyonu.
- **Operatör ekseni (MongoDB):** `$ne` (eşit değil — auth bypass), `$gt`/`$gte`/`$lt` (karşılaştırma — sonuç kümesi), `$regex` (`{"$regex":"^a","$options":"i"}` — blind char-extraction), `$where` (JS eval — varsa KRİTİK, RCE-vari), `$in`/`$nin` (liste), `$exists`.
- **CouchDB ekseni:** Mango `_find` selector'una operatör (`{"selector":{"user":{"$gt":null}}}`); `_all_docs`/`_design` view erişimi; HTTP API doğrudan (yetki yoksa BOLA).
- **Tip ekseni:** array vs object enjeksiyonu; iç içe alan (`user.role[$ne]`); `$ne` yerine `[$ne][]` array varyantı.
- **JS injection (`$where`/`mapReduce`):** boolean (`this.user=='a'||'1'=='1'`), time (`sleep`), yan-etki. Her eksen hipotez; deterministik fark yoksa "operatör enjekte edilemiyor" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Her JSON 200'ü açık sanmak:** API'nin JSON kabul etmesi enjeksiyon değildir; operatörlü/operatörsüz DAVRANIŞ farkı şart.
- **Cast edilmiş girdiyi enjeksiyon sanmak:** Backend `String(input)` / Mongoose typed schema yapıyorsa `{"$ne":null}` literal stringe döner, hiçbir etki olmaz — fark yoksa FP.
- **Hata mesajını bypass sanmak:** parse hatası (400/500) ≠ sorgu kontrolü.
- **Negatif kontrolsüz iddia:** `$ne` ile farklı cevap gördün diye atlama; düz-string negatif kontrolü etkiyi operatöre bağlamalı.
- **`$where` time'ını ağ jitter ile karıştırmak:** `sleep(0)` negatif kontrolü olmadan time iddiası yok; ayrıca `$where` çoğu prod'da kapalıdır.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** auth bypass veya sonuç-kümesi farkı (veya blind oracle) + N tekrar + düz-string negatif kontrolü etkiyi doğruladı.
- **Sinyal yok, kapat:** JSON+query+form eksenlerinde operatör hiç parse edilmedi / davranış sabit kaldı (cast var).
- **Şüpheli, ilerle:** operatörle hafif fark var ama negatif kontrol eksik → bir hedefli teyit isteği (veya `$regex` blind oracle), sonra karar.

## ÖZET — 5 KURAL
1. JSON'un kabul edilmesi değil, operatörle DAVRANIŞ değişimi açığın kanıtıdır.
2. `{"$ne":null}` auth bypass'ını yanlış-parola RED'i ile yan yana göster.
3. `[$ne]` (geniş) vs `[$gt]` (boş) karşıtlığıyla sonuç farkını ölç; veri yoksa `$regex` blind oracle.
4. Operatörü düz-string olarak geçiren negatif kontrol olmadan iddia etme.
5. JSON tıkalıysa `param[$ne]=` query/form bracket notasyonunu dene; `$where` time'ını `sleep(0)` ile çıpala.
