---
name: vuln-deserialization
description: >
  Insecure Deserialization sınıfı: kullanıcı-kontrollü veri bir deserializer'a
  (PHP unserialize/phar, Java, Python pickle, .NET, Node, Ruby) gidiyorsa uygulanır.
  Serialized objenin işlenip bir gadget chain tetikleyip tetiklemediğini bulur.
  Ana karar: gadget GERÇEKTEN tetiklendi mi (OOB/time/davranış), yoksa sadece
  base64 mü gördük?
---

# 🧬 INSECURE DESERIALIZATION — kullanıcı verisi deserializer'a gidiyor ve gadget TETİKLENİYORSA açıktır

> **Tek cümle:** Bir serialized obje deserializer'a geçiyorsa, güvenli (yıkıcı OLMAYAN) bir gadget'la onu işlet; kanıt "base64 gördüm" değil, gadget'ın fiilen çalıştığını gösteren OOB callback / zaman gecikmesi / gözlemlenebilir davranıştır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-ssrf]] [[vuln-command-injection]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Kullanıcı-kontrollü bir alan bir deserializer'a ulaşıyorsa: cookie/session değeri, `__VIEWSTATE` (.NET), gizli form alanı, `?data=` base64, mesaj kuyruğu/cache payload'u, API gövdesinde serialized blob, dosya upload (PHP phar).
- **Magic byte / prefix ile DİL TEŞHİSİ (önce bunu yap):**
  - **Java:** ham bytes `ac ed 00 05`; base64'te `rO0AB...` ile başlar; `Content-Type` çoğu zaman `application/x-java-serialized-object`.
  - **PHP:** `O:8:"ClassName":N:{...}` (obje), `a:N:{...}` (dizi), `phar://` stream sarmalı.
  - **Python pickle:** opcode `\x80\x04` / `\x80\x02` (proto), sonu `.` (STOP); base64'te `gAS...`/`gAJ...`.
  - **.NET:** BinaryFormatter base64 `AAEAAAD/////...`; ASP.NET `__VIEWSTATE` (base64, MAC korumalı olabilir); `LosFormatter`/`ObjectStateFormatter`.
  - **Node:** `node-serialize` `_$$ND_FUNC$$_function...`.
  - **Ruby:** Marshal `\x04\x08` magic; base64 `BAh...`.
- SKIP: veri sadece JSON.parse/normal parse ediliyorsa (gadget yürütme yok). Prototype pollution ise → [[vuln-prototype-pollution]]. Format tanınmıyor ve hiçbir magic byte eşleşmiyorsa muhtemelen düz encoding'tir, SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici durum taşımak için objeyi serialize edip istemciye verip geri okuyor olabilir. Deserialize sırasında magic metotlar (`__wakeup`/`__destruct`, `readObject`, `__reduce__`, `readResolve`, Marshal `_load`) otomatik çalışır → saldırgan-kontrollü obje grafiği = kod akışı.
- Kaçırılan yer: istemciden gelen serialized veriyi imzasız/şifresiz güvenmek; whitelist (allowed classes / type filtering) olmadan deserialize; `TypeNameHandling.All` (Json.NET) gibi tip-bilgisini açan ayar; "kendi verim, kimse dokunamaz" varsayımı.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Mevcut serialized değeri yakala; decode et, formatı/sınıf adlarını teşhis et (magic byte/opcode/prefix ile dil tespiti). Bozulmamış değerle normal istek; status + body + süre not. request_id sakla.
- **İmza kontrolü ÖNCE:** değer HMAC/şifre/MAC ile korunuyorsa (örn. Rails `--<base64>`, imzalı cookie, MAC'li `__VIEWSTATE`), anahtar bilinmeden forge ETME — orada dur, sinyal yok kapat. Yalnız ham/imzasız serialized'da ilerle.
- **Tek prob (kademeli, YIKICI DEĞİL):**
  1. **Yüzey teyidi:** geçerli serialized objeyi minimal değiştir (örn. PHP'de uzunluk alanını/bir byte'ı boz) → deserializer hatası mı, sessiz mi? Hata mesajı (sınıf/opcode/stack) deserialize edildiğini doğrular; salt taşıma ise çoğu zaman fark etmez.
  2. **OOB prob (asıl kanıt):** dilin güvenli OOB gadget'ı ile benzersiz collaborator domain'e DNS/HTTP çağrısı tetikle — OS komutu DEĞİL (bkz. §6 GADGET KATALOĞU; örn. Java `URLDNS`, PHP `SoapClient`/phar SSRF). Callback geldi mi?
  3. **Time prob:** OOB yoksa, ölçülebilir gecikme üreten güvenli gadget; baseline'a karşı tutarlı +Nsn mi? Negatif kontrol: gecikmesiz varyant ≈ baseline.
- **Cypture notu:** Serialized değeri taşıyan alanı (cookie/header/gövde) `cyp_send_request` ile aynen yerleştir; base64/gzip/url-encode katmanlarını baseline'dan çıkardığın doğru sırayla uygula. Collaborator/OOB callback'i payload'a göm, dönen request_id ile callback token'ını eşleştir. [[engine-mcp-contract]].

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Bozuk serialized → deserializer'a özgü hata (PHP `unserialize()`, Java `readObject` stack, pickle `UnpicklingError`, .NET `SerializationException`); VEYA OOB gadget'tan benzersiz token'lı DNS/HTTP callback; VEYA güvenli time gadget'tan tutarlı gecikme.
- **Gürültü (aday DEĞİL):** Cevapta base64/serialized görmek (sadece taşınıyor olabilir); jenerik 500; girdinin yansıması; WAF bloğu. **base64 ≠ deserialization.**

## 5. DOĞRULAMA KAPISI (kanıt)
- **OOB-based (en güçlü, çoğu blind):** payload'a gömülü benzersiz alt-alan adı collaborator'da kayıtlı; request_id ↔ callback token eşleşir. Bu deserializer'ın objeyi instantiate edip gadget'ı sürdüğünü kanıtlar.
- **Time-based:** güvenli gecikme gadget'ı ≈ baseline+Nsn, 3 tekrar; negatif kontrol (gecikmesiz varyant) ≈ baseline. Jitter delta'yı yutmamalı.
- **Davranış:** hata sınıfı/stack'in deserialize yolunu göstermesi destekleyici kanıt; tek başına yeterli değil, OOB/time ile birleştir.
- Her kanıt = baseline request_id + tetikleyici request_id (+ OOB token eşleşmesi).

## 6. VARYASYON / BYPASS — GADGET KATALOĞU (dile/framework'e göre)
Önce kütüphane fingerprint'i çıkar (hata stack'i, sürüm header'ı, cookie adı), sonra OOB-yetenekli, YIKICI-OLMAYAN chain seç. ysoserial/ysoserial.net üretici araçtır; çıktıyı doğru katmanla (base64/gzip) sar.
- **Java (ysoserial):** keşif için `URLDNS` (gadget-bağımsız, salt DNS — en güvenli ilk prob). Chain'ler: `CommonsCollections3`/`CommonsCollections4` (commons-collections kütüphanesi varsa), `CommonsBeanutils1`, `Spring1`/`Spring2`, `JRMPClient`/`JRMPListener` (OOB TCP). Magic `ac ed 00 05` / base64 `rO0`. Çıktıyı çoğu zaman base64'le; bazen gzip.
- **.NET (ysoserial.net):** `ObjectStateFormatter`/`LosFormatter` → ASP.NET `__VIEWSTATE` (MAC kapalıysa veya `validationKey` sızdıysa). `Json.NET` `TypeNameHandling != None` ise tip-confusion gadget'ı. `BinaryFormatter` base64 `AAEAAAD/////`. Formatter'a göre gadget seç (`--gadget`, `--formatter`).
- **Python (pickle):** `__reduce__` ile tek-callable çağrısı en temiz keşif; `c__builtin__\neval\n` / `cos\nsystem` opcode kalıbı. OOB için `urllib`/`socket` çağırt, OS komutu yerine DNS lookup tetikle. Sonu `.` (STOP) olmalı.
- **PHP (POP chain):** `O:` serialized obje; magic metot `__wakeup`/`__destruct`/`__toString`. Hazır POP chain'ler kütüphaneye göre: Monolog, Guzzle, Laravel (`Illuminate`), Symfony — phpggc üreticisi. `phar://` ile dosya-op (`file_exists`/`fopen`) üzerinden tetikleme (`O:` gönderemediğin sink'lerde). SoapClient/SSRF en güvenli OOB.
- **Ruby (Marshal):** `\x04\x08` magic; `Marshal.load` ile gadget. universaldeserialization/`Gem::*` chain'leri; OOB için ERB/`Net::HTTP` çağırt.
- **Encoding ekseni:** base64, URL-encode, gzip, deflate katmanları; sunucunun beklediği katman sırasını baseline'dan çıkar — yanlış sıra "çalışmıyor" yanılgısı verir.
- **Allowed-class bypass ekseni:** type-filtering/whitelist varsa izinli sınıflar içinde OOB tetikleyen bir alt-gadget ara. Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **base64'ü deserialization sanmak:** EN BÜYÜK tuzak. Cevapta/cookie'de base64 görmek, sunucunun onu UNSERIALIZE ettiğini göstermez; çoğu base64 sadece encoding'dir. Önce magic byte ile dili TEŞHİS et.
- **500'ü açık sanmak:** bozuk payload'a 500 = girdi parse edilemedi olabilir; gadget tetiklenmedikçe (OOB/time) açık değil.
- **Yansımayı kanıt sanmak:** serialized string'in cevapta görünmesi gadget yürütmesi değildir.
- **OOB'siz "blind RCE" iddiası:** kör senaryoda OOB veya time kanıtı yoksa kanıt yoktur.
- **Yıkıcı gadget kullanmak:** dosya silen/yazan/komut çalıştıran chain hedefe zarar verir; DAİMA güvenli (URLDNS/SSRF/DNS) gadget'la kanıtla.
- **İmzalı veriyi forge etmeye çalışmak:** HMAC/MAC anahtarı yokken imzalı blob'u değiştirip "denedim" demek zaman kaybı ve gürültüdür; imza varsa anahtar bulunmadıkça açık değil.
- **Yanlış gadget'ı "kapalı" sanmak:** chain hedefte o kütüphane yoksa çalışmaz; fingerprint'e göre doğru chain'i seç, tek chain'le kapatma.
- **Hata mesajını tek başına kanıt saymak:** deserialize stack'i yüzeyi doğrular ama gadget yürütmesini KANITLAMAZ; OOB/time olmadan "exploit edildi" deme.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** OOB callback / time delta+negatif kontrol / deserializer-spesifik davranış (OOB ile desteklenmiş) — + N tekrar.
- **Sinyal yok, kapat:** format/dil/sink/gadget-ailesi eksenleri denendi; ne OOB ne time ne deserialize hatası; veri muhtemelen yalnızca taşınıyor veya imza koruyor.
- **Şüpheli, ilerle:** deserialize hatası alındı ama gadget tetiklenemedi (uygun chain yok gibi) → fingerprint'i netleştir, bir OOB-hedefli güvenli prob daha, sonra karar.

## ÖZET — 5 KURAL
1. Önce magic byte ile dili TEŞHİS et; base64 ASLA kanıt değil — deserialize ve gadget tetiklenmesini ayrıca kanıtla.
2. Çoğu deserialization blind'dır → kanıt OOB callback (en güçlü), sonra time.
3. DAİMA güvenli/yıkıcı-olmayan gadget kullan (Java URLDNS, PHP SoapClient, pickle DNS); fingerprint'e göre doğru chain'i seç.
4. 500/yansıma kanıt değildir; imzalı/MAC'li veriyi anahtarsız forge etme.
5. Her kanıt = baseline request_id + tetikleyici request_id + OOB token eşleşmesi.
