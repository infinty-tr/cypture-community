---
name: vuln-email-injection
description: >
  E-posta / SMTP header injection sınıfı: ad, konu, alıcı, gönderen gibi kullanıcı
  alanları bir maile string olarak giriyorsa uygulanır. CRLF ile yeni header
  enjekte ederek gizli BCC/ek alıcı, header smuggling, mailer şablon enjeksiyonu.
  Ana karar: girdi mail HEADER yapısını değiştiriyor mu (yeni satır geçiyor),
  yoksa sadece gövdeye düz metin mi giriyor?
---

# ✉️ EMAIL / SMTP HEADER INJECTION — girdiyle mailin başlık yapısını kır, gizli alıcı/header ekle

> **Tek cümle:** Mail alanına CRLF kaçırıp yeni bir header satırı yazdır; kanıt, kendi kontrolündeki adrese düşen kopya (BCC) veya enjekte ettiğin header'ın teslim edilen mailde görünmesidir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[out-of-band-testing]] [[vuln-ssti]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Kullanıcı girdisi bir e-posta üretiyorsa: parola sıfırlama, "bana ulaş"/contact, davet/invite, paylaş, abone ol, fatura gönder, hesap doğrulama.
- Enjekte edilebilir alanlar: gönderen adı, `from`/`reply-to`, `subject`, `to`/`cc`, alıcı e-postası, dinamik "X seni davet etti" adı.
- İpuçları: forma e-posta/ad/konu girince mail tetiklenmesi; OOB için mail kopyasını yakalayabileceğin adres (kendi mailbox'ın / collaborator catch-all).
- SKIP: Hiç mail üretmeyen akış. Girdi yalnızca gövdeye düz metin olarak giriyor ve header'ları framework tamamen sabitliyorsa header-injection yoktur (ama mailer template-injection'a bak → [[vuln-ssti]]).

## 2. İNSAN MUHAKEMESİ
- Geliştirici girdiyi mail başlığına concatenation ile koymuş olabilir: `"From: " + name + "\r\n"`. Modern mailer kütüphaneleri CRLF'i temizler; eski/elle yazılmış SMTP kodu temizlemez.
- Mantık: `\r\n` (CRLF) bir header satırını bitirip yenisini başlatır. `\r\nBcc: attacker@x` enjekte edilirse mailer bunu meşru header sanıp ek alıcı ekler.
- Kaçırılan yer: validation'ın sadece `\n`'i temizleyip `\r`'yi (veya tersini), ya da yalnızca `to` alanını filtreleyip `subject`/`name`'i bırakması; URL-encode/Unicode CRLF'in decode sonrası geçmesi.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Akışı temiz değerlerle çalıştır; tetiklenen maili (kendi adresinde/OOB) yakala, `To/From/Subject/Bcc` header setini ve gövdeyi not al. request_id + alınan mailin header dump'ı sakla.
- **Tek prob (BCC enjeksiyonu):** Bir alana CRLF + yeni header gömüp gönder; alıcı alanı veya ad alanı en kuvvetlisi:
  - `name=Test%0d%0aBcc:%20probe@<oob>` (URL bağlamında); JSON'da `"name":"Test\r\nBcc: probe@<oob>"`.
- **Gözlem:** `probe@<oob>` adresine/collaborator'a maili kopyası DÜŞTÜ mü? Düştüyse header injection.
- **Tek prob (header görünürlüğü):** Enjekte et `...%0d%0aX-Injected:%20cypture-<rastgele>` → teslim edilen mailin RAW header'larında bu satır var mı? (BCC kanıtlanamadığında ucuz teyit.)
- Her probu `cyp_send_request` ile gönder; CRLF varyantlarını (`%0d%0a`, `%0a`, `%0d`, ham `\r\n`) ayrı dene — hangisi geçiyor izole et.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Enjekte edilen BCC adresine mail kopyası geldi; VEYA `X-Injected` header'ı teslim edilen mailde ayrı satır olarak göründü; VEYA `Subject`/`From` enjeksiyonla beklenenden farklı bölündü.
- **Gürültü (aday DEĞİL):** Payload mailin GÖVDESİNDE düz metin olarak `Test\r\nBcc: probe@x` şeklinde tek parça görünüyor (header'a geçmemiş) → injection değil. Form 400/validation reddi de değil. Tek bir mailin gecikmesi de değil.

## 5. DOĞRULAMA KAPISI (kanıt)
- **BCC:** Enjekte adres collaborator/kendi-mailbox'ında UNIQUE token'lı; o adrese mail GELDİ, baseline (enjeksiyonsuz) istekte GELMEDİ. Negatif kontrol net.
- **Header smuggling:** Teslim edilen mailin raw header'ında `X-Injected: cypture-<token>` AYRI satır; gövdede değil header bölgesinde. 2 farklı token ile tekrar üret → sabit değil.
- **Alan izolasyonu:** Hangi form alanı + hangi CRLF varyantının geçtiğini request_id ile belgele.
- Her iddia: tetikleyen istek request_id + yakalanan mailin header kanıtı (token eşleşmeli).

## 6. VARYASYON / BYPASS (bloklanınca)
- **CRLF varyantı:** `\r\n` filtreliyse sadece `\n` veya sadece `\r`; URL-encode `%0d%0a`, çift encode `%250d%250a`, Unicode/overlong, `%E5%98%8A%E5%98%8D` (UTF-8 fullwidth CR/LF kaçışı bazı parser'larda).
- **Alan ekseni:** `to` filtreliyse `name`/`subject`/`reply-to`/`cc` alanını dene — genelde sadece alıcı sertleştirilir.
- **Header ekseni:** `Bcc:` engelliyse `Cc:`, ya da `Content-Type: text/html` enjekte edip HTML mail + içerik kontrolü; folding (satır başı boşlukla devam) ile filtre atlatma.
- **Encoding ekseni:** RFC 2047 encoded-word (`=?utf-8?B?...?=`) ile konuda CRLF taşıma; çok-baytlı karakterle filtre senkronu kırma.
- **Mailer template injection:** Alan bir şablon motoruna (Twig/Jinja/Handlebars) giriyorsa `{{7*7}}`/`${7*7}` → değerlendirme → SSTI ekseni (→[[vuln-ssti]]); bu header değil, gövde/template sink'i.
- Her eksen bir hipotez; CRLF varyantları + 3-4 alan denenip ne BCC ne header görünürse "header injection sinyali yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Payload'ın mail GÖVDESİNDE düz metin görünmesini injection sanmak. Header bölgesine geçmediyse (ek alıcı yok, yeni header satırı yok) bulgu yok.
- Form validation 400'ünü "engellendi ama açık" sanmak — reddedildiyse mail hiç gitmedi, kanıt yok.
- Kendi gönderdiğin mailin sana normal teslimini "BCC kanıtı" sanmak — enjekte ettiğin AYRI adrese gelmeli, negatif kontrol şart.
- `\r\n`'i yansımada görüp mail yakalamadan iddia etmek — teslim edilen mailin raw header'ını görmeden header injection kanıtlanamaz; OOB/mailbox erişimi olmadan ancak "şüpheli" yaz.
- SSTI sonucunu (`49`) header injection sanmak — ikisi farklı sink; doğru sınıfa yaz.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Enjekte BCC adresine kopya geldi VEYA enjekte header teslim edilen mailde ayrı satır olarak göründü + negatif kontrol temiz + token eşleşti.
- **Sinyal yok, kapat:** CRLF varyantları (\r\n/\n/\r/encode/çift-encode) + 3-4 alan denendi; payload ya reddediliyor ya yalnızca gövdede düz metin kalıyor, ek alıcı/header yok.
- **Şüpheli, ilerle:** Mail kopyasını yakalayacak OOB kanal yok ama yansımada CRLF korunuyor → kanal kurulana kadar "ŞÜPHELİ: CRLF temizlenmiyor, teslim doğrulanamadı", ilerle.

## ÖZET — 5 KURAL
1. Hedef HEADER yapısı: CRLF ile yeni satır geçip ek alıcı/header yazdırabiliyor musun — gövdeye metin yazmak değil.
2. Önce baseline maili yakala; sonra TEK alana CRLF+`Bcc:`/`X-Injected` probu gönder.
3. Kanıt = enjekte BCC'ye gelen kopya VEYA teslim edilen mailin raw header'ındaki ayrı satır + negatif kontrol.
4. Payload sadece gövdede düz metinse injection DEĞİL; form reddi de değil.
5. Bloklanınca CRLF varyantı, alan (to/name/subject/reply-to), header tipi (Cc/Content-Type), encoding eksenlerini dene; mailer şablonsa SSTI'ya geç; boşsa kapat.
