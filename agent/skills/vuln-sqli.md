---
name: vuln-sqli
description: >
  SQL Injection sınıfı: kullanıcı girdisi bir SQL sorgusuna string olarak
  giriyorsa uygulanır. error/UNION/boolean-blind/time-blind ile DB'nin sorgu
  yapısını değiştirip değiştiremediğimizi bulur. Ana karar: girdi sorgu
  MANTIĞINI değiştiriyor mu, yoksa sadece 500 mü dönüyor?
---

# 💉 SQL INJECTION — girdi sorgu metnini, sadece veriyi değil, değiştiriyorsa açıktır

> **Tek cümle:** Girdiyi veri sanan parser'ı kod yazmaya ikna et; kanıt, kontrollü iki istek arasındaki ÖLÇÜLEBİLİR farktır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-nosqli]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi bir RDBMS sorgusuna (MySQL/Postgres/MSSQL/Oracle/SQLite) gidiyorsa: arama, filtre, sıralama (`ORDER BY`), `id=`, login, sayfalama, `WHERE`/`LIKE` parametreleri.
- İpuçları: parametre adı (`id`, `user`, `sort`, `q`, `category`), tek tırnak gönderince davranış değişmesi, sayısal alanların aritmetiğe tepki vermesi.
- SKIP: girdi yalnızca NoSQL/doküman store'a gidiyorsa → [[vuln-nosqli]]. Girdi hiç DB'ye ulaşmıyorsa (statik/echo) SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici girdiyi string concatenation ile sorguya gömmüş olabilir: `"... WHERE id='" + input + "'"`. Prepared statement kullansaydı kapalı olurdu.
- Mantık: tek tırnak sorgu literalini erken kapatır → syntax kırılır (error-based) veya mantık değişir (boolean/time).
- Kaçırılan yer: ORM kullanıp ham `raw()`/`ORDER BY` kolon adını parametrize etmemek, ya da "sayısal" sandığı alanı tırnaksız enjekte edilebilir bırakmak.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** orijinal isteği değiştirmeden gönder (send_request), status + body uzunluğu + cevap süresini not et. request_id sakla.
- **Tek prob (kademeli):**
  1. Tek `'` ekle → syntax kırıldı mı (DB hatası / 500 / farklı body)?
  2. Kırıldıysa `''` (çift tırnak ile dengele) → baseline'a GERİ döndü mü? Bu, kırılmanın tesadüf değil tırnağa bağlı olduğunu gösterir.
  3. Mantık çifti: `' OR '1'='1` vs `' AND '1'='2` → sonuç kümesi mantıkla değişiyor mu (biri çok satır, diğeri sıfır)?
  4. Time: yalnızca yukarıdakiler belirsizse → `'; SELECT SLEEP(5)-- -` benzeri (engine'e göre `pg_sleep`, `WAITFOR DELAY`).

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `'` kırıyor + `''` düzeltiyor; VEYA `OR 1=1`/`AND 1=2` arasında deterministik içerik farkı; VEYA SLEEP(5) tutarlı +5sn gecikme, SLEEP(0) gecikmesiz.
- **Gürültü (aday DEĞİL):** her girdide dönen jenerik 500/WAF blok sayfası; sadece "garip" görünen ama `''` ile düzelmeyen body; tek seferlik yavaş cevap.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Error-based:** `'` → DB error string, `''` → baseline. İki request_id ile göster.
- **Boolean-blind:** TRUE payload = içerik A, FALSE payload = içerik B; en az 2-3 tekrar deterministik.
- **Time-blind:** SLEEP(5) ≈ baseline+5sn (3 tekrar), negatif kontrol SLEEP(0) ≈ baseline. Ağ jitter'ını ele: delta net ve tekrar üretilebilir olmalı.
- Her iddia için baseline request_id + tetikleyici request_id zorunlu.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Bağlam/tırnak:** çift tırnak `"`, tırnaksız sayısal (`1 OR 1=1`), `ORDER BY 1` / `ORDER BY 9999`.
- **Encoding:** URL-encode, çift URL-encode, yorum varyantı (`--+`, `#`, `/**/`).
- **Engine fingerprint:** `SLEEP` (MySQL) vs `pg_sleep` (PG) vs `WAITFOR` (MSSQL) — hangisi tutarsa engine o.
- **Sink/metot:** JSON body / header / cookie içindeki parametreyi dene; GET tıkalıysa POST.
- Her eksen bir hipotez; 3-5 denemede sinyal yoksa dürüstçe "SQLi sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Jenerik 500'ü SQLi sanmak:** Çoğu 500 input validation/null/encoding hatasıdır. `''` ile baseline'a dönmüyorsa SQLi DEĞİL.
- **Ağ gecikmesini time-based sanmak:** Tek yavaş cevap kanıt değil. SLEEP(0) negatif kontrolü gecikmesizse ve SLEEP(5) tekrar tekrar +5sn ise kanıt.
- **WAF blok sayfasını "farklı cevap" sanmak:** WAF her şüpheli inputa aynı sayfayı verir; bu mantık farkı değildir.
- **Reflected error mesajını sömürülebilirlik sanmak:** hata görünmesi ≠ sorgu kontrolü; mantık/time ile teyit et.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** baseline↔tetikleyici farkı (error/boolean/time) + N tekrar + negatif kontrol geçti.
- **Sinyal yok, kapat:** tırnak/mantık/time eksenleri denendi, hiçbiri deterministik fark üretmedi.
- **Şüpheli, ilerle:** belirsiz davranış var ama henüz negatif kontrol yok → tek hedefli prob daha, sonra karar; istek bütçesini boşa harcama.

## ÖZET — 5 KURAL
1. Önce baseline al, sonra TEK prob gönder — kör payload listesi püskürtme.
2. `'` kırdıysa `''` ile düzeltebildiğini kanıtla; düzelmiyorsa SQLi değil.
3. Boolean için TRUE/FALSE çiftini deterministik tekrarla göster.
4. Time-based'i SLEEP(0) negatif kontrolü olmadan ASLA iddia etme.
5. Her kanıt = baseline request_id + tetikleyici request_id; gerisi spekülasyon.
