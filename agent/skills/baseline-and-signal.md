---
name: baseline-and-signal
description: >
  Anti-brute-force ve sinyal disiplini. Bir bulgu iddia etmeden önce baseline'dan ölçülebilir
  sapma + tekrar zorunlu. Sinyal ile gürültüyü ayırma, insan-benzeri akıllı test sırası, kör
  payload spam yerine hipoteze dayalı dar test. Tüm test ajanları bunu uygular.
---

# 📊 BASELINE & SİNYAL DİSİPLİNİ — KÖR BRUTE-FORCE'A KARŞI

> **Tek cümle:** Önce normalin ne olduğunu ölç (baseline). Bir şeyi "açık" sayman için
> baseline'dan ÖLÇÜLEBİLİR ve TEKRARLANABİLİR bir sapma görmen gerekir. Sapma yoksa açık yoktur.

İnsan bir pentester körlemesine 1000 payload atmaz. Birini atar, yanıta bakar, ne öğrendiğini
düşünür, sonra bir sonrakini ona göre seçer. Bu modül o davranışı zorunlu kılar.

---

## 1. BASELINE ÖNCE — her input için (atlanamaz)

Bir parametreyi/header'ı test etmeden önce normal davranışını ölç:

```
Zararsız değer gönder (örn. "test123"), KAYDET:
  - statusCode (200/302/400/500)
  - yanıt süresi (ms) — en az 2-3 kez at, ortalama al (tek ölçüm güvenilmez)
  - body boyutu (byte)
  - Content-Type
  - değerin yanıtta yansıyıp yansımadığı + bağlam (HTML body / attr / script / JSON / hiç)
```

Bu baseline olmadan hiçbir sapma "anlamlı" sayılamaz. Baseline = ölçü birimin.

---

## 2. SİNYAL TANIMI — neyi "açık adayı" sayarsın

Sadece şu sapmalar sinyaldir (baseline'a göre):

| Sinyal | Baseline | Tetiklenmiş | Yorum |
|---|---|---|---|
| Zaman | ~50 ms | 5000+ ms (sadece SLEEP payload'ında) | Time-based enjeksiyon adayı |
| Hata sızıntısı | 200 temiz | 500 + DB/stack mesajı | Enjeksiyon/işleme hatası adayı |
| Boolean fark | `'1'='1` → X kayıt, `'1'='2` → 0 kayıt | mantıksal sapma | Blind SQLi adayı |
| Yetki | A→403/404 | A token'ı B kaynağında 200 + B'nin verisi | IDOR/BOLA adayı |
| Yansıma | reflection yok | payload HAM yansıyor (encode YOK), çalışır bağlamda | XSS adayı |
| Hesap | `{{7*7}}` → `49` | matematik sunucuda işlendi | SSTI adayı |

**Sinyal DEĞİL (gürültü):** salt `200 OK`; WAF blok sayfası; jenerik 403/404; her değere aynı
yanıt; tek seferlik gecikme (ağ); encode edilmiş/etkisiz yansıma; eksik güvenlik header'ı tek başına.

---

## 3. İKİ KAPI — bulgu iddiasından önce

```
KAPI A — ÖLÇÜLEBİLİR SAPMA:
  Baseline ile tetiklenmiş yanıt arasında somut, ölçülebilir fark var mı?
  (kod / ms / boyut / içerik / yetki) — "hissettim" değil, sayı/alıntı.

KAPI B — KONTROLLÜ TEKRAR + NEGATİF KONTROL:
  1. Aynı payload 2-3 kez → fark tutarlı mı? (tek seferlik ise gürültü)
  2. Negatif kontrol: ZARARSIZ benzeri payload aynı sapmayı YAPMAMALI.
     (örn. SLEEP(5) yavaşlatıyorsa SLEEP(0) yavaşlatmamalı — yoksa gecikme ağdandır)
```

İki kapıdan da geçemeyen şey bulgu değil → "ŞÜPHELİ"ye yaz. (bkz. [[evidence-discipline]])

---

## 4. AKILLI TEST SIRASI — insan gibi düşün, kör spam yapma

```
1. GÖZLEMLE: Input ne işe yarıyor? (arama/id/fiyat/url/dosya...) → bağlamı anla.
2. DARALT: Bağlam hangi 1-2 zafiyet sınıfını mümkün kılıyor? SADECE onları test et.
   (bir 'id' parametresine XSS wordlist'i atmak = boşa token. Önce IDOR/SQLi mantıklı.)
3. TEK PROB: Önce TEK bir teşhis payload'ı at (örn. tek `'`), yanıta bak, ne öğrendin?
4. KARAR: Sinyal varsa derinleş; yoksa o sınıfı "❌ (ne denendi, neden yok)" diye kapat.
5. ASLA: "Tüm payload listesini sırayla dene" yapma. Her payload bir öncekinin
   cevabına göre seçilir. Liste tüketmek değil, soru cevaplamak.
```

> Teknoloji uyumsuzsa ATLA: PHP'de Prototype Pollution test etme, statik sayfada SQLi arama.
> firstphase.md'deki teknoloji-zafiyet matrisi önceliği belirler.

---

## 5. WAF / RATE-LIMIT FARKINDALIĞI

- Aynı endpoint'e art arda agresif istek = WAF tetikler + token yakar + gürültü üretir.
- 403/429 başladıysa: DUR, yavaşla, isteği gözden geçir. Daha fazla payload ATMA.
- WAF blok yanıtını "açık yok" diye yorumlama; "WAF araya girdi, farklı vektör/encoding gerek" de.

---

## 6. MOTOR ANALİZ ARAÇLARI — YANITI GÖZÜNLE DEĞİL, ARAÇLA İNCELE

Motor (cypture) artık request/response'u TAM yakalıyor (gövde kırpılmıyor; kesilirse yanıtta
`truncated:true` + gerçek `length` görürsün) ve dikkatli analiz için araçlar sunuyor. Koca
gövdeyi okuyup göz kararı yorumlama — bu araçları kullan:

- **`cyp_analyze_response {id}`** — her İLGİNÇ yanıtı ÖNCE bununla oku: status, content-type,
  title, form'lar+input adları, parametreler, Set-Cookie bayrakları (HttpOnly/Secure/SameSite),
  güvenlik başlıkları (var/yok), **hata/sızıntı imzaları** (SQL hata, stack trace, sızan yol, sürüm).
- **`cyp_reflect {id}`** (veya `{id, value}`) — payload gönderdikten sonra yansımayı BUNUNLA
  doğrula: değer yanıtta nerede, hangi bağlamda (html-text / attribute / js / json / header) ve
  ENCODE'lu mu? XSS/SSTI/header-injection kararını göz kararı değil buna göre ver.
- **`cyp_set_baseline {key,id}` + `cyp_diff_requests {a,b}`** — boolean/blind/authz testinde:
  temiz yanıtı baseline işaretle, payload yanıtını diff'le. `status_differs`, `length_delta`,
  `time_delta_ms`, `body_equal`, `first_diff_at`, **`header_diff`** döner. 1=1 vs 1=2, A-kimliği vs
  B-kimliği, header'lı vs header'sız — hepsi bununla.
- **`cyp_replay_request {id, set_headers/set_params/body/method, follow_redirects}`** — bir isteği
  EDİT ederek tekrar gönder (Repeater): WAF bypass varyantı, parametre/header değişimi. Otomatik
  orijinalle diff döner; redirect zinciri için `follow_redirects:true`.

---

## ÖZET — 6 KURAL

1. Önce baseline ölç (2-3 kez), o senin ölçü birimin → kritikse `cyp_set_baseline` ile sabitle.
2. Sadece tanımlı sinyaller açık adayıdır; 200/WAF/403 gürültüdür.
3. İki kapı: ölçülebilir sapma + tekrar/negatif kontrol. Geçemezse "şüpheli". Sapmayı `cyp_diff_requests` ile ÖLÇ.
4. Bağlama göre 1-2 sınıfı test et, tek prob at, cevaba göre ilerle. Liste tüketme.
5. WAF/429 görünce dur ve yavaşla; pes etme, `cyp_replay_request` ile varyant dene.
6. Her ilginç yanıtı `cyp_analyze_response` ile yapısal oku, payload yansımasını `cyp_reflect` ile doğrula.
