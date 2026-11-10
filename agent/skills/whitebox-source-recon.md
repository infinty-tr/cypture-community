---
name: whitebox-source-recon
description: >
  GREY-BOX kaynak keşfi. Operatör hedefin kaynağını verdiğinde ($WS/source) codebase'i
  haritala: stack, giriş noktaları, route tablosu, auth/authz middleware, tehlikeli
  sink'ler, config/secret. Çıktı = canlı testi yönlendiren aday listesi. Kaynak HİPOTEZ
  üretir; KANIT daima canlı endpoint'tedir (bkz. [[core-contract]] 3c).
---

# SKILL: Grey-box Kaynak Keşfi (whitebox-source-recon)

> ÖN KOŞUL: `$WS/source/` var mı? (`[ -d "$WS/source" ]` / `jq .source $WS/source.json`).
> YOKsa bu skill ATLANIR — pure blackbox devam. VARsa oku; dış internetten kaynak çekme YASAK.

Amaç: canlı yüzeyi körlemesine fuzzlamak yerine, kaynaktan **nereye bakılacağını** çıkar.
Kaynak = harita; motor = kanıt. Her bulguyu `file:line` → **canlı endpoint** eşlemesiyle bırak.

## 1. STACK & MANİFEST (nereden başla)
`$WS/source/SOURCE_SUMMARY.md` zaten diller/framework/LOC/entry adaylarını verir — ONDAN başla.
Manifest = bağımlılık + sürüm hazinesi:
- `go.mod` / `package-lock.json` / `requirements.txt` / `pom.xml` / `composer.json` → savunmasız
  bağımlılık sürümleri (→ [[vuln-known-cve]], canlı imzayla doğrula).
- `.env*`, `config/*`, `settings.py`, `application.yml`, `appsettings.json` → hardcoded secret,
  default kimlik, debug=true, açık CORS, zayıf JWT secret (→ canlı endpoint'te sömürülebilirliği teyit).

## 2. ROUTE TABLOSU (saldırı yüzeyi = gerçek endpoint listesi)
Framework'e göre route tanımlarını çıkar; kör dizin-fuzz yerine GERÇEK endpoint'leri al:
- Go: `http.HandleFunc`, `mux.Handle`, `r.Get/Post`, chi/gin/echo router çağrıları.
- Node/Express: `app.get/post/put/delete`, `router.<m>`. NestJS: `@Get/@Post/@Controller`.
- Python: Flask `@app.route`, Django `urlpatterns`, FastAPI `@app.get`.
- PHP: Laravel `Route::`, Symfony `#[Route]`. Java: `@RequestMapping/@GetMapping`, Spring `@RestController`.
Her route için not: metod, path, handler fonksiyonu, beklenen auth. `$WS/source_routes.md`'e yaz
→ recon-agent'ın canlı `urls.txt`'i ile kıyasla (kaynakta var ama canlıda görünmeyen = gizli endpoint).

## 3. AUTH / AUTHZ SINIRI (en değerli bölge)
- Middleware zincirini bul: hangi route'lar auth gerektiriyor, hangileri PUBLIC?
  (ör. `RequireAuth`, `@PreAuthorize`, `login_required`, guard'lar). Auth DEKORATÖRÜ EKSİK olan
  state-değiştiren route = missing-auth adayı (→ [[vuln-bfla]] / canlı doğrula).
- Ownership kontrolü: handler kullanıcı-verdiği `id`'yi `WHERE owner = current_user` olmadan mı
  kullanıyor? = IDOR adayı (→ [[vuln-idor]], A-vs-B kimlikle canlı kanıtla).
- Rol kontrolü: admin-only fonksiyon sadece UI'da mı gizli, backend'de kontrol yok mu? = BFLA.

## 4. TEHLİKELİ SINK'LER (taint hedefleri — detay [[whitebox-sast]])
Sink'leri grep'le, sonra kullanıcı-girdisine kadar geri izle:
- SQL: string-concat / f-string / `fmt.Sprintf` ile sorgu, `.raw(`, `$where`.
- Komut: `exec`, `system`, `os/exec`, `child_process`, `subprocess`, `Runtime.exec`.
- Dosya: `open`, `readFile`, `os.ReadFile`, `include`/`require` dinamik yolla → LFI/traversal.
- Şablon: kullanıcı girdisi template string'ine → SSTI. Deser: `pickle`, `yaml.load`, `unserialize`.
- SSRF: kullanıcı URL'si ile outbound `http.Get`/`fetch`/`requests.get`.

## 5. ÇIKTI (orkestratöre ver)
`$WS/source_findings.md` — her satır: `SINIF | file:line | kısa gerekçe | CANLI DOĞRULAMA: <endpoint+prob>`.
Bu liste orkestratörün "KAYNAK ANALİZİ" dalgasının ürünüdür → web/api/fuzz uzmanlarına beslenir.
Asla "kaynakta gördüm, bulgu" DEME — her zaman "kaynak işaret etti → canlı teyit et" de.
