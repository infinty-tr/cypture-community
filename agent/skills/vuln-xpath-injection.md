---
name: vuln-xpath-injection
description: >
  Kullanıcı girdisi bir XPath/XQuery ifadesine (XML-backed login, arama,
  konfigürasyon sorgusu) string olarak giriyorsa uygulanır. `' or '1'='1`,
  node traversal, blind boolean/substring ile sorgu mantığını ele alır.
  Ana karar: girdi XPath AĞACINI mı değiştiriyor, yoksa sadece "eşleşme yok" mu?
---

# 🌲 XPATH / XQUERY INJECTION — girdi XML sorgusunun mantığını değiştiriyorsa açıktır

> **Tek cümle:** Girdiyi veri sanan XPath ifadesine mantık enjekte edip ağacı kontrolüne al; kanıt, kontrollü iki istek arasındaki ÖLÇÜLEBİLİR auth/sonuç farkıdır.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[chain-attack-builder]] [[data-flow-and-mental-model]] [[request-economy]] [[vuln-sqli]] [[vuln-ldap-injection]] [[attacker-mindset-and-persistence]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi bir XPath/XQuery ifadesine gidiyorsa: XML dosyası/DB ile kullanıcı doğrulama (`//user[name/text()='<girdi>' and pass/text()='<girdi>']`), XML arama, konfig/katalog sorgusu, SOAP/XML API filtreleri.
- İpuçları: backend'in XML store olduğunu gösteren işaretler (`.xml` konfig, SOAP, "no XML element matches"), tek tırnak gönderince davranış değişmesi, login'in DB değil dosya tabanlı görünmesi.
- SKIP: girdi RDBMS'e gidiyorsa → [[vuln-sqli]]; LDAP filtresine → [[vuln-ldap-injection]]. Girdi hiç XML sorgusuna ulaşmıyorsa SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici XPath'i string concatenation ile kurmuş: `"//user[name='" + input + "']"`. Parametrize XPath / değişken binding kullansaydı kapalı olurdu.
- Mantık: tek tırnak XPath literalini erken kapatır → syntax kırılır; `' or '1'='1` predicate'i her zaman TRUE yapar (tüm node'lar eşleşir); `' or ''='` aynı etki. XPath'ta yorum/şema yetkisi yoktur ama `position()`, `count()`, `substring()`, `name()` ile ağaç gezilir.
- Kaçırılan yer: login'i XML'e karşı yapan eski uygulama, ya da arama predicate'ine girdiyi escape'siz koyan kod.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** girdiyi değiştirmeden gönder (`cyp_send_request`); status + body uzunluğu + sonuç/login sonucunu not et. request_id sakla. Negatif kontrol: var olmayan kayıt → "eşleşme yok".
- **Tek prob (kademeli):**
  1. Tek `'` ekle → syntax kırıldı mı (XPath hata / 500 / farklı body)? `''` ile dengele → baseline'a döndü mü (kırılmanın tırnağa bağlı olduğunu gösterir).
  2. Mantık çifti: `' or '1'='1` (her şey eşleşir → çok sonuç / login) vs `' and '1'='2` (hiçbir şey → sıfır sonuç). Deterministik fark var mı?
  3. Auth bypass: kullanıcı alanına `' or '1'='1` veya `admin' or '1'='1` → giriş oldu mu; negatif kontrol meşru-yanlış parolada reddediyor mu.
  4. Blind boolean/substring: `' or substring(//user[1]/password,1,1)='a` → TRUE/FALSE deterministik mi (karakter karakter exfil mümkün). `count(//user)=N` ile node sayısı sorgulanabiliyor mu.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `'` kırıyor + `''` düzeltiyor; `' or '1'='1` ↔ `' and '1'='2` arasında deterministik içerik/login farkı; `substring(...)='a'` boolean'ı tekrar tekrar TRUE/FALSE ayrımı veriyor.
- **Gürültü (aday DEĞİL):** her girdide jenerik 500/"eşleşme yok"; `''` ile düzelmeyen body; tek seferlik garip cevap; WAF blok sayfası; tırnağın text olarak yansıyıp mantık değiştirmemesi.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Error/syntax:** `'` → XPath/parse error veya kırık body, `''` → baseline. İki request_id.
- **Boolean mantık:** `or '1'='1` = içerik/sonuç A, `and '1'='2` = içerik B; 2-3 tekrar deterministik.
- **Auth bypass:** `' or '1'='1` → kimliği doğrulanmış oturum/redirect; negatif kontrol meşru-yanlış reddediyor. Token/Set-Cookie/redirect farkını request_id'lerle göster.
- **Blind exfil:** `substring(//user[1]/password,1,1)='a'` zinciriyle karakter karakter çıkarımın deterministik olduğunu somut diziyle göster.
- Her iddia için baseline request_id + tetikleyici request_id zorunlu.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Tırnak/bağlam:** çift tırnak `"`, `' or ''='`, `' or 1=1 or ''='`, predicate dışına çıkma `']|//*['`.
- **Encoding:** URL-encode, çift URL-encode, XML entity (`&apos;`, `&#39;`), SOAP gövdesinde CDATA kaçışı.
- **Node/fonksiyon ekseni:** `name(/*[1])`, `count(//*)`, `string-length()`, `substring()`, `position()`, `local-name()` ile blind ağaç gezme; XQuery hedefse `for $x in ...` enjeksiyonu.
- **Sink/metot:** JSON/SOAP body, header, cookie içindeki parametre; GET tıkalıysa POST; login alanı tıkalıysa parola alanı.
- Her eksen bir hipotez; 3-5 denemede sinyal yoksa dürüstçe "XPathi sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Jenerik 500'ü XPathi sanmak:** Çoğu 500 validation/encoding hatasıdır. `''` ile baseline'a dönmüyorsa açık DEĞİL.
- **`or '1'='1`'in işe yaramamasını görmezden gelmek:** Mantık çifti deterministik fark üretmiyorsa (TRUE ve FALSE aynı sonuç) injection yok demektir.
- **SQLi ile karıştırmak:** XPath'ta `--`/`#` yorum yoktur, `UNION` yoktur; sinyal mantık predicate'i + node fonksiyonlarıdır. Yanlış engine fingerprint yapma.
- **Tırnak yansımasını sömürülebilirlik sanmak:** Tırnağın body'de görünmesi ≠ sorgu kontrolü; mantık çiftiyle teyit et.
- **WAF blok sayfasını "farklı cevap" sanmak:** her şüpheli inputa aynı sayfa; mantık farkı değil.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** mantık değişti (boolean fark / auth bypass / substring exfil) + N tekrar + negatif kontrol + `''` ile düzelme.
- **Sinyal yok, kapat:** tırnak/mantık/node-fonksiyon/encoding eksenleri denendi; hiçbiri deterministik fark üretmedi.
- **Şüpheli, ilerle:** `'` kırıyor ama mantık çifti henüz net değil → tek hedefli prob daha (boolean veya substring), sonra karar; istek bütçesini boşa harcama.

## ÖZET — 5 KURAL
1. Önce baseline + negatif kontrol al, sonra TEK prob — kör payload püskürtme yok.
2. `'` kırdıysa `''` ile düzeltebildiğini kanıtla; düzelmiyorsa XPathi değil.
3. `or '1'='1` ↔ `and '1'='2` mantık çiftini deterministik tekrarla göster.
4. Blind exfil'i `substring()` boolean zinciriyle karakter karakter kanıtla.
5. Her kanıt = baseline request_id + tetikleyici request_id; XPath'ı SQLi gibi `UNION`/`--` ile karıştırma.
