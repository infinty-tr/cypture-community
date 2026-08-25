# Sistem gibi düşün — "endpoint avcısı" değil, uygulamayı ANLAYAN

> Bu sözleşme dört davranışsal eksiği yapı dayatarak kapatır (zayıf modelde bile):
> uygulamayı bir SİSTEM olarak modelle, hedefi ADAPTİF rakip gör, YOKLUĞU sinyal say,
> önseli çapa yapma. Endpoint'leri tek tek "payload dene" modunda test etme — önce ne
> olduğunu anla, sonra DEĞİŞMEZLERİNİ (invariant) kır.
> İlişkili: [[business-logic-reasoning]] [[access-control-reasoning]] [[chain-attack-builder]]
> [[attacker-mindset-and-persistence]] [[redteam-primitives]] [[evidence-discipline]]

---

## 1. YAŞAYAN UYGULAMA MODELİ — `$WS/app_model.json` (recon sonrası ZORUNLU)

Recon biter bitmez, test etmeden ÖNCE, hedefi bir sistem olarak modelle ve `$WS/app_model.json`'a yaz.
Her dalga sonunda güncelle (yeni rol/akış/sink keşfedince). Şablon:

```json
{
  "type": "e-ticaret | saas | api | cms | bankacılık | ...",
  "roles": ["anon","user","seller","admin"],
  "entities": [{"name":"order","owner_field":"user_id","states":["cart","pending","paid","shipped"]}],
  "workflows": [{"name":"checkout","steps":["sepete_ekle","kupon_uygula","öde","onayla"],"money":true}],
  "trust_boundaries": ["anon→user: /login","user→admin: /admin","tenant_A→tenant_B: org_id"],
  "value_sinks": ["/checkout=para","/admin/users=yetki","/export=veri","/api/keys=sır"],
  "invariants": [
    "kullanıcı yalnız KENDİ order'ını görür/değiştirir",
    "kupon bir kez kullanılır; fiyat >= 0",
    "ödeme onaylanmadan state 'paid'/'shipped' olamaz",
    "yalnız admin /admin/* çağırabilir",
    "tenant A, tenant B'nin verisine erişemez"
  ]
}
```

**Test = bir invariant'ı KIRMAYI dene.** Her invariant → bir hipotez:
- "kullanıcı yalnız kendi order'ını görür" → IDOR/BOLA (başka id, başka tenant).
- "kupon bir kez" → yarış (`cyp_race_send`), replay.
- "ödeme onaylanmadan paid olamaz" → state-skip (adımı atla, `cyp_sequence` ile sırayı boz).
- "yalnız admin /admin/*" → BFLA (user token'ıyla admin endpoint).

Endpoint listesi tüketmek DEĞİL — **değer-sink'lerindeki ve güven-sınırlarındaki invariant'ları** sırayla kır. En değerli buglar (iş-mantığı, yetki, çok-adımlı) sadece burada çıkar.

---

## 2. SAVUNMA MODELİ — hedef STATİK değil, ADAPTİF rakip

Blok (403/429/captcha/WAF) = "aşılacak gürültü" DEĞİL, **savunma sinyali**. Bir savunma modeli tut
(`$WS/app_model.json` içinde `defense` alanı): `{waf:true/false/?, blocked_shapes:["<script>","' OR"],
rate_limit:{eşik:"~30/dk",kapsam:"ip|hesap"}, detection:["5 istekte 403","captcha çıktı"]}`.

Blok gelince ÖNCE teşhis et, sonra adapt et (kör ısrar etme):
1. **Neyi blokladı?** payload-şekli mi (→ mutasyonla: encoding/case/HPP, [[redteam-primitives]] §5), hesap mı (→ kimlik döndür), IP mi (→ ancak o zaman yavaşla/rotasyon)?
2. **Adapt et**, aynı şeyi tekrar gönderme.
3. **Savunmanın KENDİSİ bulgu olabilir:** "tek kontrol IP rate-limit" / "WAF yok" / "kritik işlemde rate-limit yok" → zayıf-kontrol bulgusu (düşük/orta, ama kaydet).

> "Beni fark ettiler mi?" diye sor — ardışık 403, ani captcha, yanıt yavaşlaması = izleniyorsun. Tempoyu/yüzeyi ona göre değiştir.

---

## 3. YOKLUK MUHAKEMESİ — "burada ne OLMALIYDI ama YOK?"

Sadece pozitif yanıta tepki verme. Her önemli yanıtta (`cyp_analyze_response` kullan — eksik başlıkları zaten çıkarır) eksik-olanı sor:
- **403 beklenirken 200?** → kırık yetki (en değerli sinyallerden).
- **Güvenlik başlığı yok mu?** (CSP/HSTS/X-Frame/SameSite) → clickjacking/aktarım/oturum riski.
- **Parametre YOK SAYILDI mı?** Gönderdim ama yanıt hiç değişmedi → ya yanlış isim ya gizli davranış (`cyp_param_mine`).
- **Rate-limit YOK mu?** 100 istek attım, hiç 429 yok → brute/kaynak-tüketimi/OTP-deneme açık.
- **State-değiştiren POST'ta CSRF token YOK mu?** → CSRF.
- **Miktar/fiyat/rol doğrulaması YOK mu?** → mass-assignment / iş-mantığı.

Yokluk, çoğu zaman varlıktan daha güçlü sinyaldir. "BİLİNMİYOR" bırakma — eksikliği test et.

---

## 4. ÖNSEL = İPUCU, ÇAPA DEĞİL (anti-anchoring)

`learned_priors` (kb.json) sıralama ipucudur: yüksek-rate sınıfı ÖNCE dene. Ama:
- **Düşük-rate'i ATLAMA** — sadece sıra, eleme değil.
- Her host'ta EN AZ bir **beklenmedik/önselsiz** sınıfı da dene — yeni stack davranışı önsele uymayabilir.
- Önsel "SQLi yüksek" diyor diye XSS/IDOR/iş-mantığını es geçme. Önsel geçmişi özetler, BU hedefi değil.

---

## 5. SEVERITY TRİAJI / BÜTÇE — düşük-seviyeyle vakit harcama

Sınırlı istek/token/zaman bütçen var; onu DEĞER'e yatır:
- **Önce yüksek-değer:** kimlik/yetki (IDOR/BFLA/priv-esc), para/veri/sır sink'leri, iş-mantığı, RCE/SQLi/SSRF. `app_model.json`'daki value-sink'ler ve invariant'lar buranın haritası.
- **Düşük-sev'de DERİNLEŞME:** eksik güvenlik başlığı, sürüm banner'ı, eksik cookie flag, "X-Frame yok→clickjacking", dizin listeleme — bunları **tek satır kaydet ve GEÇ**. Her biri için ayrı derin PoC/varyant üretme; gerekiyorsa topluca kaydet.
- **Pivot kuralı:** bir yüzeyde 2-3 düşük-değer denemeden sonra güçlü sinyal yoksa BAŞKA endpoint/sınıfa geç — rabbit-hole'a girme, aynı yeri eşeleme.
- **Yüzde-90 kuralı:** bütçenin çoğu critical/high adaylarını SÖMÜRMEYE (potansiyel→kanıt) gitmeli; düşük-sev tarama-doldurma EN SON ve hızlı. "Çok sayıda info bulgusu" değil, "az sayıda kanıtlı yüksek-etki" hedef.

---

## NOT — bunlar yapı; bazı şeyler beyin ister

Yukarıdakiler zayıf modelde bile davranış dayatır. Ama **etkiden-geriye planlama** (önce hedef-etki,
sonra zincir), **inanç-durumu sürekliliği** (ne doğrulandı/elendi NEDEN — dalgalar/ajanlar arası unutma),
ve **kalibre durma yargısı** büyük ölçüde modelin muhakeme gücüne bağlıdır — güçlü/frontier modelde belirgin
biçimde daha iyidir. Zayıf modelde: app_model.json + savunma modeli + dalga-sonu güncelleme, hafızanın
yerini kısmen tutar (durumu dosyada tut, kafanda değil).
