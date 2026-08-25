---
name: engine-mcp-contract
description: >
  Cypture MCP araçlarının ZORUNLU kullanım sözleşmesi. Tüm HTTP trafiği Cypture üzerinden
  gider — curl değil. Araç adı keşfi, ham HTTP şablonu, scope, session/cookie yönetimi,
  bulgu kaydı ve request_id loglama protokolü. TÜM test/keşif ajanları bunu uygular.
---

# 🔌 CYPTURE MCP KULLANIM SÖZLEŞMESİ

> **Tek cümle:** Hedefe giden HER istek MOTORDAN geçer — tercihen `cyp_send_request`, araç yoksa
> `curl -x http://127.0.0.1:8080` (proxy de motora gider, loglanır). PROXY'SİZ doğrudan `curl https://hedef` YASAKTIR.
> Sebep: izlenebilirlik (her istek loglanır), tekrar edilebilirlik (replay), kanıt (request_id),
> ve token tasarrufu (yanıtlar Cypture'da kalır, bağlamı şişirmez).

---

## 0. ARAÇLAR HER ZAMAN MEVCUTTUR — DOĞRUDAN KULLAN (keşif/şüphe YOK)

**"Cypture" = bizim KENDİ motorumuz (cypture-engine), dış bir uygulama DEĞİL.** Konteynerin içinde
gömülü ve her zaman çalışır → "köprü yok / araç mevcut değil" diye bir durum YOKTUR. Araçlar şu
TAM adlarla sunulur (ikisi de geçerlidir, hangisini görürsen onu kullan):

```
cyp_send_request   (veya kısa: send_request)
cyp_create_finding (veya kısa: create_finding)
cyp_search_history (veya: search_history)   cyp_get_request (veya: get_request)
cyp_batch_send · cyp_diff_requests · cyp_list_sessions · cyp_get_session_cookies ...
```

> Önce `cyp_send_request`'i dene; runtime onu farklı önekle sunduysa (`cyp_cyp_send_request`,
> `mcp__cyp__...`) ya da kısa `send_request` olarak görüyorsan ONU kullan — hepsi AYNI motora gider.
> Adı keşfetmek için tur harcama; doğrudan çağır.

**İLK ÇAĞRI HATA/TIMEOUT VERİRSE:** motor daha yeni ısınıyordur — **2 sn bekle, TEKRAR DENE** (3 kez).
Çoğu zaman ikinci deneme çalışır. **Hiçbir "köprü/server KURMA"** — npm/pip ile kurulacak bir şey YOKTUR,
o yola sapma (boşa tur harcarsın).

**3 denemeden sonra `cyp_send_request` araçları GERÇEKTEN oturumunda yoksa** (bazı alt-ajan oturumlarında
MCP köprüsü yüklenmeyebilir): panik yok, "manuel kayıt" da deme — bunun yerine **`curl -x http://127.0.0.1:8080`
kullan.** Bu proxy DAİMA açıktır ve artık her isteği motorun history+feed'ine LOGLAR (MITM) → kanıt sayılır,
panelde `req` olarak görünür, `cyp_create_finding` request/response'u oradan otomatik iliştirir.
**MUTLAK KURAL:** curl DAİMA `-x http://127.0.0.1:8080` ile gider — proxy'siz/doğrudan `curl https://hedef`
ASLA atılmaz (loglanmaz, scope'tan geçmez, feed'i boşaltır = req=0 hatası). Tercih sırası: önce
`cyp_send_request` (raw-socket smuggling / race-window / iki-kimlik session gibi özellikleri var), yoksa
`curl -x 127.0.0.1:8080`. İkisi de motordan geçer, ikisi de loglanır.

**BULGU KAYDI — İKİ KANAL, İKİSİ DE ZORUNLU (yoksa bulgu PANELE DÜŞMEZ):**
1. **`cyp_create_finding`** (veya `create_finding`) çağır — bulgunun panele düşmesinin BİRİNCİL yolu.
   Motor bunu otomatik feed'e yazar; özet/anlatı bulgu SAYILMAZ.
2. **EK GÜVENCE:** her bulguyu `bash`/`write` ile `/cyp/findings.ndjson`'a TEK SATIR JSON olarak ekle —
   bu düz dosya yazımıdır, hiçbir araç/MCP GEREKTİRMEZ. create_finding'den şüphelensen bile bu satır
   bulguyu garanti panele düşürür. Örn:
   `bash: printf '%s\n' '{"title":"...","severity":"high","endpoint":"...","poc":"...","verified":true}' >> /cyp/findings.ndjson`

> Özet: motor her zaman orada. Aracı keşfetme — kullan. Hata olursa tekrar dene. Bulguyu HEM
> create_finding HEM /cyp/findings.ndjson'a yaz. "dahili kayıt"/firstphase.md bulgu kanalı DEĞİLDİR.

---

## 1. İSTEK GÖNDERME — `cyp_send_request`

**Parametreler:**
- `raw` (zorunlu) — Başlıklar + body dahil HAM HTTP isteği.
- `host` — Hedef host (Host header'ı ezer).
- `port` — Port (TLS'e göre varsayılan).
- `tls` — HTTPS için `true` (varsayılan true).
- `sessionId` — Replay session ID (oturum gruplaması için, opsiyonel).
- `bodyLimit` — Yanıt body byte limiti (varsayılan 2000). **Token tasarrufu için küçük tut.**
- `bodyOffset` — Body okuma başlangıcı (büyük yanıtı parça parça okumak için).
- `useCookieJar` — Aynı `sessionId`'de Set-Cookie otomatik taşınır. Tek seferlik kapatmak için `false`.

**Döndürür:** `statusCode`, `headers`, `body`, ve (zaman aşımında) takip için `entryId`.

### Ham istek şablonu (KOPYALA, payload'ı değiştir)

```
cyp_send_request(
  host = "app.hedef.com",
  tls  = true,
  raw  = "GET /api/v1/users?id=42 HTTP/1.1\r\nHost: app.hedef.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
)
```

POST / JSON örneği:

```
cyp_send_request(
  host = "app.hedef.com",
  raw  = "POST /api/login HTTP/1.1\r\nHost: app.hedef.com\r\nContent-Type: application/json\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"user\":\"test123\",\"pass\":\"test123\"}"
)
```

**Kurallar:**
- Satır sonları `\r\n`. Başlıklarla body arasında BOŞ satır (`\r\n\r\n`).
- `Content-Length` body'nin gerçek byte uzunluğuyla eşleşmeli (yanlışsa backend isteği bozar).
- Kimlikli istekler için `Authorization` / `Cookie` başlığını ekle (aşağıdaki session yönetimine bak).

---

## 2. İLK ADIM — SCOPE OLUŞTUR (`cyp_create_scope`)

Test başlamadan önce hedefi scope'a al. Kapsam dışına istek = kural ihlali.

```
cyp_create_scope(
  name = "hedef",
  allowlist = ["hedef.com", "*.hedef.com"],
  denylist  = []   # test izni olmayan subdomainleri buraya
)
```

> Değerler hostname'dir — şema (`https://`) veya path YAZMA.

---

## 3. SESSION & COOKIE YÖNETİMİ

- Aynı kullanıcının oturumunu paylaşan istekler **aynı `sessionId`** ile gider → Set-Cookie otomatik taşınır.
- **IDOR/BOLA/BFLA için iki ayrı kimlik gerekir:** `sessionId="kullaniciA"` ve `sessionId="kullaniciB"`.
  Böylece A'nın token'ıyla B'nin kaynağına erişimi temiz test edersin, cookie'ler karışmaz.
- Kimliksiz baseline için `useCookieJar=false` veya yeni `sessionId` kullan.
- Token süresi dolarsa: yeniden login isteği at, yeni token'ı not et, eski istekleri tekrar etme.

---

## 4. GEÇMİŞ & YENİDEN OKUMA — token'ı koru

- Yanıtı tekrar görmek için isteği **YENİDEN GÖNDERME**. `cyp_get_request(ids=[...])` ile çağır.
  Varsayılan sadece metadata döner (ucuz). Gövde gerekirse `include=["responseBody"], bodyLimit=1500`.
- Bir deseni geçmişte aramak için `cyp_search_history(pattern, scope="response")` —
  yeniden tarama yapmadan "bu hata mesajı başka nerede geçiyor" sorusunu cevaplar.
- Büyük yanıtı tek seferde çekme: `bodyLimit` + `bodyOffset` ile pencere pencere oku, sadece gerekeni al.

---

## 5. BULGU KAYDI — `cyp_create_finding`

Bir bulguyu DOĞRULADIKTAN sonra (bkz. [[evidence-discipline]], [[baseline-and-signal]]) Cypture'ya işle:

```
cyp_create_finding(
  requestId   = "<kanıt isteğinin ID'si>",
  title       = "IDOR — /api/v1/users/{id} yetkisiz erişim",
  description  = "A token'ı ile B'nin kaydı 200 döndü. Baseline: 403. 3 kez tekrar edildi."
)
```

> `requestId` ZORUNLU — gerçek, loglanmış bir isteğe bağlı olmayan bulgu kaydedilmez.

---

## 6. İLERİ ARAÇLAR (gerektiğinde, körlemesine değil)

| İhtiyaç | Araç | Ne zaman |
|---|---|---|
| Aynı isteği N payload ile | `cyp_run_intruder` | Parametre/değer listesi denemesi — ama önce hipotez (bkz. baseline) |
| Çoklu istek tek seferde | `cyp_batch_send` | İlişkili birkaç isteği toplu at |
| Race condition | `cyp_race_window_send` | Eşzamanlılık testi (double-spend, TOCTOU) |
| Replay oturumu/koleksiyonu | `cyp_create_replay_session` / `_collection` | Bulguları düzenli grupla |
| Encode/decode | `cyp_encode_decode` | base64/url/jwt parçalama — yerel, token ucuz |

> **Intruder/batch token yakar.** Sadece net bir hipotez + sonlu, gerekçeli bir liste varsa kullan.
> "10.000 kelimelik wordlist'i kör at" = YASAK (bkz. [[baseline-and-signal]], [[request-economy]]).

---

## 7. CURL KULLANIMI

İki durum:
1. **Yerel pipe** (hedefe GİTMEYEN işler — bir çıktıyı `grep`/`jq`'ye bağlamak): çıplak `curl` serbest.
2. **Hedefe giden istek, `cyp_send_request` oturumda YOKKEN:** `curl -x http://127.0.0.1:8080` kullan —
   proxy motordan geçer, MITM ile loglanır (history+feed, request_id, kanıt). **`-x http://127.0.0.1:8080`
   ŞART**; proxy'siz/doğrudan `curl https://hedef` ASLA — o istek görünmez kalır (req=0).

Örnek dokümanlarda çıplak `curl -H "..."` görürsen bu sadece **payload'ı/başlığı gösterir** — o isteği
`cyp_send_request` şablonuyla, o yoksa `curl -x 127.0.0.1:8080` ile gönder.

---

## ÖZET — 6 KURAL

1. Araç adını başta bir kez keşfet, hep onu kullan.
2. Scope oluştur, sonra test et.
3. Her hedef isteği `cyp_send_request` ile gider. curl yok.
4. Aynı kimliği `sessionId` ile taşı; IDOR için iki ayrı session.
5. Yanıtı tekrar görmek için yeniden gönderme — `get_request`/`search_history` kullan.
6. Bulguyu `requestId` ile `cyp_create_finding`'e işle. Kanıtsız bulgu yok.

## İNTERAKTİF TARAYICI (gerçek Chromium) — İÇERİĞİ SADECE ÇEKME, İNCELE
Ham HTTP yetmediğinde GERÇEK tarayıcı araçlarını kullan (motor lazily Chromium başlatır, scope zorunlu):
- `cyp_browser_navigate{url,waitMs}` — JS'i çalıştırıp render edilmiş sayfayı döndürür. Dönen `dialogs` (ör. "alert: 1") DOLU ise enjekte script ÇALIŞTI → DOM-XSS'in KANONİK kanıtı (executed_effect).
- `cyp_browser_dom{}` — JS sonrası render edilmiş outerHTML. SPA/JS-ağır sayfada içeriği GÖZ KARARI değil BUNUNLA analiz et (gizli sink, client-side route, form).
- `cyp_browser_eval{expr}` — sayfa bağlamında JS çalıştır (document.cookie, localStorage, innerHTML; sink tetikle).
- `cyp_browser_screenshot{}` — PNG görsel kanıt; `path` döner. Çalışan/ciddi bulguda GÖRSEL KANIT al ve `path`'i bulgunun `extracted_evidence` alanına yaz.
NE ZAMAN: SPA/JS-render içerik analizi; DOM-XSS'i gerçekten ATEŞLEMEK; client-side kontrolü atlamak; doğrulanan bulguya görsel kanıt. Halüsinasyonu bunlarla kır — "olabilir" deme; ATEŞLE ve GÖR. (→ [[evidence-discipline]]: dialogs/screenshot = executed_effect)
