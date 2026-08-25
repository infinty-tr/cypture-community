---
name: vuln-subdomain-takeover
description: >
  Subdomain takeover sınıfı: bir alt alan adı (CNAME/DNS) artık sağlanmayan
  (deprovisioned) bir üçüncü-parti servise işaret ediyorsa uygulanır. Dangling
  kayıt + servisin "claim edilmemiş" imzası = saldırgan o subdomain'i ele
  geçirebilir. Ana karar: CNAME canlı bir servise mi, yoksa boş/claimable bir
  kovaya/sayfaya mı gidiyor — GERÇEKTEN claim ETMEDEN kanıtla.
---

# 🪧 SUBDOMAIN TAKEOVER — dangling CNAME + claim edilmemiş servis imzası açıktır

> **Tek cümle:** Bir subdomain, terk edilmiş bir üçüncü-parti servise işaret ediyorsa kanıt = (CNAME kaydının o servise gittiği) + (servisin "bu kaynak yok / claim edilebilir" fingerprint'i); takeover'ı GERÇEKTEN yapmadan, imzayla göster.

İlişkili: [[recon-and-wildcard-enum]] (subdomain keşfi) [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Recon'da bulunan her alt alan adı için: bir CNAME (veya A/AAAA) üçüncü-parti barındırma servisine işaret ediyor ve o kaynak provider tarafında SAĞLANMIYOR.
- İpuçları: `*.<hedef>` wildcard enum'dan çıkan eski/unutulmuş subdomain (`blog`, `staging`, `cdn`, `docs`, `mail`, `status`, eski kampanya adları); 404/NoSuchBucket/"not found"; CNAME → `*.s3.amazonaws.com`, `*.github.io`, `*.herokuapp.com`, `*.azurewebsites.net`, `*.fastly.net` vb.
- SKIP: subdomain kendi altyapına (apex'in IP'si) çözülüyorsa; CNAME canlı, claim edilmiş, içerik sunuyorsa; NXDOMAIN (kayıt yoksa dangling de yok).

## 2. İNSAN MUHAKEMESİ
- Ekip bir servis (S3 kovası, GH Pages, Heroku app) açıp DNS'te CNAME bırakmış; sonra servisi SİLMİŞ ama DNS kaydını UNUTMUŞ. Şimdi o ada herkes kaydolabilir → subdomain artık saldırganın.
- Etki: o subdomain'de içerik yayınlama (phishing, çerez çalma — subdomain cookie scope, OAuth redirect, CORS güveni). Güven mirası yüzünden yüksek değerli.
- Asıl mesele: kayıt DANGLING mi (hedef servis boş + claimable) yoksa sadece geçici 404 mü? Karar fingerprint kataloğuyla verilir, varsayımla değil.

## 3. TEŞHİS PROB'U (önce baseline DNS, sonra TEK HTTP prob)
- **Baseline (DNS çözümleme):** Subdomain'in CNAME zincirini çöz; hangi üçüncü-parti servise gittiğini ve apex'e mi yoksa dış servise mi indiğini not et. Bu, "dangling adayı mı" kararının temeli.
- **Tek prob (HTTP fingerprint):** Subdomain'e `cyp_send_request` ile tek istek (Host header subdomain olacak); dönen status + body'yi servis imzasıyla eşle:
  ```
  GET / Host: <hedef-subdomain>   → 404 + servise özgü "claim edilebilir" imzası mı?
  ```
- **Fingerprint kataloğu (servis → claimable imza):**
  | Servis | CNAME deseni | Claimable imza (body/status) |
  |---|---|---|
  | AWS S3 | `*.s3*.amazonaws.com` | `NoSuchBucket` / "The specified bucket does not exist" |
  | GitHub Pages | `*.github.io` | 404 "There isn't a GitHub Pages site here" |
  | Heroku | `*.herokuapp.com` | "No such app" / `no-such-app.herokuapp.com` |
  | Azure | `*.azurewebsites.net`/`*.cloudapp.net`/`*.trafficmanager.net` | 404 site/"Web Site not found" / NXDOMAIN'e düşen CNAME |
  | Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
  | Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
  | Cloudfront/diğer | sağlayıcı CNAME'i | sağlayıcıya özgü "not configured/not found" |

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** CNAME bilinen bir servise gidiyor + HTTP yanıtı o servisin TAM claimable imzasını içeriyor (yukarıdaki katalog) + o ad provider'da kayıtlı görünmüyor.
- **Gürültü (aday DEĞİL):** Jenerik 404 (uygulamanın kendi 404'ü, servis imzası YOK); WAF/CDN "access denied"; CNAME canlı içeriğe gidiyor; geçici 5xx/timeout; "private bucket" (var ama erişim kapalı — claimable DEĞİL).

## 5. DOĞRULAMA KAPISI (kanıt — claim ETMEDEN)
- **İki parçalı kanıt:** (1) CNAME kaydı X servisine işaret ediyor (DNS çıktısı), (2) X servisi o kaynak için TAM claimable imzayı dönüyor (HTTP request_id'li body). İkisi birlikte = takeover mümkün.
- **Claim edilebilirlik teyidi (saldırgan eylemi YAPMADAN):** İmza katalogla birebir; mümkünse provider'ın "bu ad kullanılabilir" sinyalini pasif kontrol et (ör. ad rezerve değil). Kovayı/app'i GERÇEKTEN oluşturma — bu non-destructive sınırı; kanıt imzadır, ele geçirme değil.
- **Negatif kontrol:** Aynı zonda CANLI bir subdomain aynı probu yiyince claimable imza DÖNMEMELİ (200/gerçek içerik) → imzanın dangling'e özgü olduğunu gösterir.
- Her iddia: DNS çözümleme çıktısı + HTTP request_id + eşlenen katalog satırı.

## 6. VARYASYON / BYPASS (imza belirsizse)
- **Recon ekseni:** Wildcard/pasif DNS, sertifika şeffaflığı (crt.sh), eski kayıtlardan daha çok subdomain çıkar → [[recon-and-wildcard-enum]]; takeover unutulmuş adlarda gizlenir.
- **Zincir ekseni:** CNAME → CNAME → servis; son halkayı çöz, ara halka yanıltır.
- **Provider-varyant ekseni:** Aynı servisin bölgesel/yeni imzaları (S3 region endpoint'leri, `403 AccessDenied` vs `404 NoSuchBucket` ayrımı — sadece NoSuchBucket claimable).
- **NS-takeover ekseni:** Dangling NS delegasyonu (zone'un tamamı claimable) — CNAME değil NS kaydını kontrol et.
- Katalogda eşleşme yoksa "imza belirsiz, claimable değil" diye dürüstçe kapat — jenerik 404'ü takeover sanma.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** Jenerik 404'ü takeover sanmak. Servise özgü claimable imza YOKSA bulgu yok.
- **`403 AccessDenied`'ı claimable sanmak:** S3'te 403 kova VAR ama özel demektir — claim EDİLEMEZ; sadece `NoSuchBucket` claimable.
- **Canlı CNAME'i dangling sanmak:** Servis içerik sunuyorsa terk edilmemiştir.
- **NXDOMAIN'i takeover sanmak:** Kayıt hiç yoksa ele geçirilecek dangling de yok (bazı provider istisnaları hariç — imzayla teyit).
- **Gerçekten claim etmek:** Kanıt için kovayı/app'i oluşturmak GEREKMEZ ve non-destructive sınırı aşar — imza yeterli kanıttır.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** CNAME bilinen servise gidiyor + o servisin TAM claimable imzası dönüyor (request_id'li) + negatif kontrol (canlı subdomain) imza dönmüyor.
- **Sinyal yok, kapat:** CNAME canlı/claim edilmiş VEYA yanıt jenerik 404/403-private; katalogda claimable imza eşleşmiyor.
- **Şüpheli, ilerle:** Servise gidiyor ama imza belirsiz (region/CNAME zinciri) → son halkayı çöz, provider-varyant imzasını dene, sonra karar.

## ÖZET — 5 KURAL
1. Önce CNAME/DNS zincirini çöz; dangling adayı = üçüncü-parti servise giden + sağlanmayan kayıt.
2. HTTP yanıtını fingerprint kataloğuyla eşle — claimable imza YOKSA takeover yok.
3. Kanıt iki parçalı: CNAME hedefi + servisin claimable imzası, ikisi de request_id'li.
4. GERÇEKTEN claim ETME (non-destructive); jenerik 404'ü ve `403 private`'ı takeover sanma.
5. Recon'dan beslen (wildcard/CT log); negatif kontrol canlı subdomain'le imzanın dangling'e özgü olduğunu doğrula.
