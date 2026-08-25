---
name: response-manipulation
description: >
  Sunucunun yanıtına ve client-tarafı güvene saldırma — hacker mantığıyla. İstemcinin
  gördüğü/gönderdiği her şey saldırgan kontrolündedir: gizli alanlar, JS'teki kontroller,
  yanıttaki status/flag/role, fiyat, "izin var mı" boolean'ı. Sunucu istemciye güvendiği
  HER yerde açık vardır. Mekanik payload değil, "bu kontrol gerçekten serverda mı?" sorusu.
---

# 🎭 RESPONSE & CLIENT-SIDE MANİPÜLASYONU — istemciye güvenen her yer kapıdır

> **Tek cümle:** İstemcinin elindeki hiçbir şey güvenli değildir — gizli alan, JS değişkeni,
> response'taki `"isAdmin":false`, disabled buton, fiyat input'u. Soru hep aynı: **"bu kontrol
> client'ta mı yoksa serverda mı? Client'taysa, ben client'ım — ihlal ederim."**

İlişkili: [[business-logic-reasoning]] [[hunter-intuition]] [[access-control-reasoning]] [[evidence-discipline]]

Bu sınıf araçla bulunmaz; uygulamanın istemciye NEYE güvendiğini görüp o güveni kırmakla bulunur.
Mekanik sinyal (hata/gecikme/yansıma) yoktur — sinyal **mantıksal tutarsızlıktır**: client'ta
"yapamazsın" denen şeyi server kabul etti.

---

## 1. GİZLİ / SALT-OKUNUR ALANLARA GÜVEN — onları sen kontrol edersin

İstemcinin gönderdiği her alan değiştirilebilir; "hidden", "disabled", "readonly" sadece UI'dır.

```
<input type="hidden" name="price" value="100">   → 1 yap, gönder. Server fiyatı yeniden hesaplıyor mu?
<input type="hidden" name="user_id" value="42">  → 43 yap (IDOR).
<input type="hidden" name="role" value="user">   → admin yap (privilege escalation).
disabled "Apply discount" butonu                  → isteğini elle kur, yine de gönder.
step="form_2" gizli alanı                          → form_3 yap (akış atlama).
```

> Refleks: formu/isteği ham gör, HER alanı "ben buna ne değer verebilirim?" diye sorgula.
> UI'nin gizlediği alan, server'ın körü körüne güvendiği alandır.

---

## 2. RESPONSE'A GÜVENME — gelen yanıt "izin" değil, GÖZLEM

İstemci uygulaması yanıttaki bir alana bakıp karar veriyorsa (UI'ı açıyor, adımı geçiriyorsa),
o kararı sen de verebilirsin — yanıtı değiştir veya bir sonraki isteği "izin verilmiş gibi" kur.

```
{"otp_verified": false}   → bir sonraki isteğe rağmen ilerle; server gerçekten tekrar kontrol ediyor mu?
{"step": "payment"}       → doğrudan "confirm" endpoint'ini çağır.
{"is_premium": false}     → premium-only isteği yine de gönder — server flag'i tekrar doğruluyor mu?
{"balance": 0} ama "withdraw" → çek; bakiye kontrolü clientta mıydı?
HTTP 302 → /dashboard (login başarısız ama yönlendiriyor) → 302'yi izleme, body'deki Set-Cookie/veri sızıyor mu?
```

> Kural: "client şuna bakıp şunu yaptı" = "server o adımı ATLAYABİLİR varsaydı". O adımı doğrudan dene.

---

## 3. STATUS CODE / AKIŞA GÜVEN — "200 geçtim" tuzağı

Uygulama (ve zayıf tarayıcı) status code'a göre karar verir; saldırgan içeriğe bakar.

```
401/403 aldın ama body'de gerçek veri VAR  → kontrol yanıtı kesmemiş, sadece "status" koymuş.
200 ama "access denied" gövdede             → tersi de olur; her zaman GÖVDEYİ oku.
İlk istek 403, ikinci (farklı sıra/parça) 200 → idempotent değil; yarış/sıra istismarı.
Multi-step: 2. adım 200 dönüyorsa 1. adımı hiç yapmadan 3. adımı dene.
```

> "200 = başarı / 403 = güvenli" yanılgısı. Karar GÖVDE + DAVRANIŞ'tan çıkar, status'tan değil.

---

## 4. CLIENT-SIDE KONTROL = SERVER-SIDE KONTROL DEĞİL

JS'te yapılan her doğrulama saldırgan için yok hükmündedir; tek soru: "server da yapıyor mu?"

```
JS regex e-posta doğrulaması     → isteği elle CRLF/<script>/dizi ile gönder.
JS "max 10 adet" sınırı          → 1000 gönder.
JS fiyat hesaplama               → toplamı elle değiştir.
client-side rate-limit (debounce)→ doğrudan 100 paralel istek (race / brute).
"Sadece resim" client filtresi   → .php / polyglot yükle.
```

> Her client kontrolünü gördüğünde: o kontrolü ATLAYAN ham isteği kur, server'ın aynı kontrolü
> yapıp yapmadığını TEK isteğle test et. Yapmıyorsa → bulgu.

---

## 5. MASS ASSIGNMENT — yanıtın şekli, isteğin de kabul edeceği şekildir

Sunucu bir nesneyi yanıtta `{"id","email","role","verified"}` olarak dönüyorsa, güncelleme
isteğinde o alanları SEN de gönderebilirsin — server allow-list'liyor mu?

```
GET /me → {"id":42,"email":"...","role":"user","credit":0}
PATCH /me {"email":"x"} çalışıyor → PATCH /me {"role":"admin","credit":99999} dene.
Yanıtta gördüğün ama formda olmayan HER alan = mass-assignment hipotezi.
```

> Refleks: response'taki alan adlarını al, isteğe geri enjekte et. Yanıt = kabul edilen alanların haritası.

---

## ÖZET — 5 REFLEKS

1. Gizli/disabled/readonly alan = server'ın körü körüne güvendiği alan; değiştir, gönder.
2. Yanıttaki flag/step/role'e göre client karar veriyorsa, o adımı doğrudan dene — server tekrar kontrol ediyor mu?
3. Status code'a değil GÖVDE + davranışa bak; "200 geçtim / 403 güvenli" yanılgısına düşme.
4. Her client-side kontrolü (JS validasyon/limit/hesap) atlayan ham isteği kur; server'da var mı diye test et.
5. Yanıtın alan şeklini al, güncelleme isteğine geri enjekte et (mass assignment).
