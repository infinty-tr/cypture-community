---
name: vuln-prototype-pollution
description: >
  SADECE JS/Node.js bağlamında uygulanır. Bir input (JSON body veya query) obje
  merge/clone/path-set sink'ine giriyorsa ve __proto__ / constructor.prototype ile
  Object.prototype kirletilebiliyorsa. Kütüphane gadget'ları (lodash merge, jQuery
  extend, qs, AJV) → RCE/XSS/auth bypass. Ana karar: kirlilik bir gadget'ı tetikledi mi.
---

# 🧬 PROTOTYPE POLLUTION (Node.js/JS) — Object.prototype'ı kirletip gadget tetikleme

> **Tek cümle:** Saldırgan-kontrollü key'ler bir JS merge/clone sink'ine girip `Object.prototype`'a özellik yazabiliyorsa, o özelliği okuyan başka kod (gadget) yoldan çıkar — DoS, prop-injection, XSS, auth-bypass, bazen RCE. PHP/Python ise SKIP.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[chain-attack-builder]] [[vuln-xss]] [[vuln-rce]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE çalışan stack **JS/Node.js** ise (Express/Fastify/Next, header `X-Powered-By: Express`, JS hata izleri/stack trace, `.js` SSR). PHP/Python/Java/Ruby ise **SKIP: PP JS'e özgü**.
- **Sink:** kullanıcı JSON/objesini **derin merge/clone/extend/path-set** eden kod:
  - `lodash.merge`/`mergeWith`/`defaultsDeep`/`set`/`setWith`, `$.extend(true,...)` (jQuery), `Object.assign` döngüsü, config merge, `qs`/`querystring` parse (`?a[__proto__][x]=1`), Express body, `deepmerge`, eski `AJV` coerce.
- **Client-side vs server-side ayrımı:** server PP = body/query merge sink'i; client PP = `location`/`postMessage`/`JSON.parse` → DOM merge (`$.extend`, `deparam`). Hangisi olduğunu veri akışıyla belirle ([[data-flow-and-mental-model]]).
- SKIP: input düz string olarak işleniyor, hiç obje-merge/path-set yok.

## 2. İNSAN MUHAKEMESİ
- JS'te `obj.__proto__` → `Object.prototype`. Recursive merge `__proto__`/`constructor.prototype` key'ini "normal" key sanıp prototype'a yazarsa, TÜM objeler o özelliği miras alır.
- Geliştirici kullanıcı JSON'unu güvenle merge ettiğini sandı; key adının prototype zincirine erişebileceğini kaçırdı. Gerçek etki, kirli özelliği OKUYAN bir **gadget**'a bağlı — pollution tek başına yarı yoldur; gadget olmadan impact yok.
- Soru: "Hangi key prototype'a yazıyor, ve hangi sonraki kod o miras özelliği okuyup davranışını değiştiriyor (gadget)?"

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Hedef endpoint'e normal JSON gönder (`cyp_send_request`), yanıt/davranışı kaydet, request_id sakla.
- **Kademeli prob:**
  1. **Kirletme + miras kanıtı:** Body'ye benzersiz marker ile `{"__proto__":{"pp_marker":"x9z"}}` (veya query `?__proto__[pp_marker]=x9z`). Ardından AYRI/ilgisiz bir endpoint'e istek at → `pp_marker` beklenmedik bir yanıt/objede MİRAS olarak belirdi mi?
  2. **Status-reflect gadget (Express):** `{"__proto__":{"status":510}}` → sonraki hata yanıtının status'u 510'a kaydı mı (Express `res.status` prototype'tan okuyabilir).
  3. **`json spaces` / `outputFunctionName` gadget:** çıktı formatı değişti mi.
  4. Doğrudan görünmüyorsa server davranış değişimini (status/JSON şekil/error) gözle.
- **Disiplin:** global state kalıcı kirlenebilir — mümkünse session/process-local etkiyle göster; kalıcı bozarsa not düş. [[request-economy]]: kör payload spreyleme değil, gadget hipoteziyle hedefli prob.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday:** Kirletme sonrası `pp_marker` ilgisiz bir yanıtta/objede MİRAS olarak görünüyor; veya bilinen gadget (status/json spaces/template option/`Allow-...`) ile gözlemlenebilir davranış değişti.
- **Gürültü:** JSON 200 kabul edildi ama hiçbir davranış değişmedi; marker sadece kendi echo'sunda göründü (miras DEĞİL, reflection); 400/validation reddi; key `__proto__` JSON.parse tarafından zaten korundu (modern V8 bazı yollarda).

## 5. DOĞRULAMA KAPISI (kanıt)
- Zincir: (1) kirletme request_id, (2) **ayrı/ilgisiz** bir istekte marker'ın miras özellik olarak göründüğü request_id (gerçek pollution kanıtı), (3) gadget davranış değişikliği (status/format/template/auth), (4) N tekrar, (5) negatif kontrol: `__proto__` yerine düz `xproto` key'i hiçbir şey değiştirmiyor (reflection'ı pollution'dan ayır).
- **Impact yükseltme (gadget'a göre):** XSS (template option/`escapeFunction` gadget → [[vuln-xss]]); RCE (`child_process` opts/`NODE_OPTIONS`/EJS `outputFunctionName` → [[vuln-rce]]); auth-bypass (eksik prop'un `true`'ya miras kalması); DoS. Sadece kanıtlanabilir gadget'ı raporla.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Anahtar varyantı:** `__proto__`, `constructor.prototype`, nested `constructor[prototype][x]` (qs/lodash path).
- **Taşıma:** JSON body vs query-string (`a[__proto__][x]=1`) vs form-encoded vs `qs` array notation.
- **Sanitizer atlatma:** `__pro__proto__to__` (key-fold), unicode/case, çift kodlama, `constructor` yolu (bazı filtreler sadece `__proto__` engeller).
- **Kütüphane gadget kataloğu (hedef stack'e göre dene):**
  - **lodash `merge`/`set`:** `merge` → genel pollution; sürüm fix'leri var, eski sürümleri dene.
  - **jQuery `$.extend(true,...)`:** client-side DOM PP.
  - **Express/qs:** `?a[__proto__][b]=c`; `status`/`json spaces` gadget.
  - **Fastify/AJV:** schema coerce/`additionalProperties` ile `__proto__` slip; `Object.create(null)` yoksa.
  - **EJS/Pug/Handlebars:** `outputFunctionName`/`escapeFunction`/template option → RCE/XSS gadget.
- **Endpoint değişimi:** aynı merge util'i kullanan başka route.
- Hiçbir gadget tetiklenmiyorsa kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- JSON'un 200 kabul edilmesini PP sanmak — gadget/miras kanıtı yoksa FP.
- Marker'ın kendi echo'sunu "pollution" sanmak (miras değil, sadece reflection); ayrı/ilgisiz okuma noktasında görünmeli.
- PHP/Python/Java uygulamada `__proto__` denemek (anlamsız) → SKIP zorunlu, önce stack doğrula.
- Client-side `__proto__` denemesini server PP sanmak (ya da tersi); akış yönünü belirle.
- Validation reddini "filtre var ama yine vuln" diye yorumlamak.
- Pollution kanıtlanmış ama gadget yok iken "RCE/XSS olabilir" diye varsaymak — somut gadget zincirini kanıtla.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** İlgisiz bir okuma noktasında miras-özellik göründü VE somut gadget davranışı (status/template/auth/RCE) değişti, N tekrar + negatif kontrol (`xproto`) tutarlı.
- **Sinyal yok, kapat:** Davranış hiç değişmedi / stack JS değil / merge sink yok / sadece reflection.
- **Şüpheli, ilerle:** Marker miras olarak görünüyor ama gadget belirsiz → §6 anahtar/taşıma/kütüphane-gadget eksenlerini dene.

## ÖZET — 5 KURAL
1. Stack JS/Node değilse SKIP — PHP/Python'da PP arama; önce stack doğrula.
2. Önce obje-merge/clone/path-set sink'i olduğunu doğrula (lodash/qs/$.extend/AJV).
3. Kanıt = ilgisiz okuma noktasında miras özellik VE gadget davranış değişikliği, salt JSON kabulü değil.
4. Negatif kontrol (`xproto` key) ile reflection'ı pollution'dan ayır.
5. Gadget tetiklenmiyorsa kapat; kanıtsız "RCE/XSS olabilir" yazma — somut gadget zinciri kur.
