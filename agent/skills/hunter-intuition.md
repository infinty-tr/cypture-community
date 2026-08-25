---
name: hunter-intuition
description: >
  Dünya-sınıfı bir bug-hunter'ın NASIL düşündüğü: gerçekten zeki olmak için sezgi.
  Zayıf sinyali iplik gibi çekme, varsayım tersine çevirme ("geliştirici neyi varsaydı?
  tersini dene"), değer-önce hedefleme (auth/para/PII/admin/parser), yaratıcı zincir
  içgüdüsü, "neden burada?" merakı, soluk sinyalin ne zaman L3 hak ettiğine karar verme,
  araç-maymunluğundan kaçınma (yorumla, dökme), çıkmazı yeni hipoteze çevirme.
  Web ve API ajanlarının "akıllı olma" beyni — playbook değil, düşünce tarzı.
---

# 🧠 DÜNYA-SINIFI AVCI SEZGİSİ — checklist değil, düşünme tarzı

> **Tek cümle:** Ortalama tarayıcı imza eşler; usta avcı SORU sorar. Aynı yanıta bakıp "200, geçtim"
> diyen ile "neden burada bu header var?" diyen arasındaki fark, bulunan ve bulunmayan açıktır.
> Bu skill bir payload listesi vermez — bir top-hunter'ın KAFASINI verir.

İlişkili: [[depth-calibration]] [[attacker-mindset-and-persistence]] [[chain-attack-builder]] [[baseline-and-signal]] [[signal-commentary]]

---

## 1. ZAYIF SİNYALİ İPLİK GİBİ ÇEK

Küçük bir anomali çekilecek bir ipliktir, gürültü değil. Usta, en ufak tutarsızlığı "ilginç" sayıp peşine düşer.

```
Zayıf: response süresi bir parametrede 40ms daha uzun.
  Tembel  → "jitter", geç.
  Usta    → "neden SADECE bu parametrede? DB mi, ek lookup mu, time-blind mi?" → izole et, tekrarla.

Zayıf: 404 yerine 403 dönen tek bir path.
  Tembel  → "yok zaten", geç.
  Usta    → "403 = VAR ama yetki yok. Demek burada bir kaynak gizli. Kim erişir?" → IDOR/BFLA hipotezi.
```

> Kural: bir sapma 2. kez tekrar üretilebiliyorsa artık "his" değil SİNYAL'dir; düş peşine ([[baseline-and-signal]]).

---

## 2. VARSAYIM TERSİNE ÇEVİRME — "geliştirici neyi varsaydı?"

Her güvenlik kontrolü bir VARSAYIMA dayanır. Avcı varsayımı bulup tersini dener.

```
Varsayım: "kullanıcı kendi id'sini gönderir"          → Tersi: başkasının id'sini gönder (IDOR).
Varsayım: "fiyat client'tan gelmez"                   → Tersi: fiyatı/quantity'yi negatif/0 yap.
Varsayım: "bu alan hep e-posta olur"                  → Tersi: CRLF/dizi/obje/<script> koy.
Varsayım: "imza geldiyse içerik güvenli"              → Tersi: imzayı koru, gövdeyi değiştir (XSW).
Varsayım: "step 2'ye step 1'den gelinir"              → Tersi: step 2'yi doğrudan çağır (akış atlama).
```

> Refleks: bir özelliği görünce "bunu yazan ne DOĞRU sandı?" diye sor, sonra o doğruyu yanlışla.

---

## 3. DEĞER-ÖNCE HEDEFLEME — nerede ekmek var

Avcı her yere eşit bakmaz; ETKİSİ yüksek yere koşar. Bir input'a bakarken ilk soru "bu nereye dokunuyor?":

```
YÜKSEK DEĞER (önce buraya kaz): auth/oturum, para/bakiye, PII/gizli veri, admin/internal,
  parser (upload/XML/şablon/deserialize), dış-istek (SSRF), tenant sınırı.
DÜŞÜK DEĞER (hızlı geç): statik içerik, versiyon sayfası, durum değiştirmeyen GET.
```

> "Burayı kırarsam ne kazanırım?" sorusu yön verir. Reflected XSS güzeldir; admin oturumu çalan
> stored-XSS veya para akışı mantığı PARADIR. Değer kalibrasyonu → [[depth-calibration]].

---

## 4. "NEDEN BURADA?" MERAKI

Usta avcı her tuhaflığa çocuk gibi "neden?" sorar — açıklanamayan her şey kapı olabilir.

```
"Neden bu endpoint bir debug parametresi alıyor?"
"Neden bu yanıtta bir iç IP / sürüm / stack izi var?"
"Neden bu redirect kullanıcı kontrollü bir url taşıyor?"
"Neden bu JSON'da kullanmadığım bir 'role' alanı var?"  → mass assignment hipotezi.
"Neden bu istek imzasız da kabul edildi?"
```

> Açıklanamayan her detay bir hipotezdir. "Garip ama önemsiz" deme — garip = sinyal.

---

## 5. YARATICI ZİNCİR İÇGÜDÜSÜ — tek açık değil, BİRLEŞİM

Top-hunter izole açık yerine zincir düşünür: tek başına düşük-etkili iki şey, birleşince kritik olur.

```
Open redirect (tek başına low)  +  OAuth token redirect  → hesap devralma.
Self-XSS (low)                  +  CSRF / login-CSRF      → tetiklenebilir stored-XSS.
IDOR ile e-posta okuma          +  parola reset akışı      → ATO.
SSRF (orta)                     +  cloud metadata          → kimlik bilgisi → tam erişim.
```

> Refleks: "bunu neyle BİRLEŞTİRİRSEM etki büyür?" Her düşük-etkili bulgu, bir zincirin halkası
> olabilir → [[chain-attack-builder]].

---

## 6. SOLUK SİNYAL: L3 HAK EDİYOR MU, BIRAK MI?

Her zayıf izin peşine düşmek de israftır. Karar: sinyalin DEĞER'i ve TEKRAR ÜRETİLEBİLİRLİĞİ.

```
DEĞER yüksek (auth/para/parser) + soluk sinyal  → L3 derin dalış HAK EDER, kaz.
DEĞER düşük (statik) + soluk sinyal             → 1 prob, tekrar üretilemiyorsa bırak.
Sinyal tekrar üretilebilir (2. kez aynı)        → artık his değil, sonuna kadar git.
Sinyal tek seferlik, açıklanabilir (jitter/cache)→ not düş, geç.
```

> "Bir prob daha" içgüdüsü: yüksek-değerli yerde HAKLI, değersiz yerde token katili.
> Farkı değer + tekrar belirler ([[depth-calibration]], [[attacker-mindset-and-persistence]]).

---

## 7. ARAÇ-MAYMUNU OLMA — YORUMLA, DÖKME

Zayıf ajan aracı çalıştırıp çıktıyı döker. Usta avcı çıktıyı OKUR, anlamlandırır, bir sonraki hamleyi kurar.

```
Araç-maymunu : "intruder çalıştırdım, 500 sonuç var." (yorum yok, ileri adım yok)
Usta avcı    : "200 dönen tek payload `||`'ydi; demek operatör enjekte oluyor; şimdi mantık çifti
               ile teyit edip boolean-blind'a geçiyorum." (gözlem → anlam → hamle)
```

> Her tool çıktısı bir sorunun cevabıdır; cevabı YORUMLA ve yeni soru üret. Ham dump akıl değildir
> → [[signal-commentary]] (her gözleme tek cümle anlam).

---

## 8. ÇIKMAZI YENİ HİPOTEZE ÇEVİR

"Çalışmadı" bir son değil, bir bilgidir. Usta her başarısızlığı yeni bir hipoteze dönüştürür.

```
"file:// bloklandı"        → "demek protokol filtresi var; http:///gopher:///php://filter dener miyim?"
"=  CSV'de eskape ediliyor"→ "ya +,-,@? ya da baştaki TAB? ya da farklı export yolu?"
"doğrudan prompt reddedildi"→ "ya saklanan içerikten DOLAYLI enjeksiyon?"
"WAF her şeyi kesiyor"      → "neyi kesiyor tam? karakteri izole et, encoding ekseni değiştir."
```

> Çıkmaz = "bu varsayımım yanlıştı, hangi varsayım hâlâ ayakta?" Her duvar, etrafından dolaşılacak
> bir varsayımı işaret eder ([[attacker-mindset-and-persistence]]).

---

## ÖZET — 7 KURAL

1. Zayıf sinyal bir ipliktir — tekrar üretilebiliyorsa peşine düş, "jitter" deyip geçme.
2. Her kontrolün bir varsayımı vardır; onu bul ve TERSİNİ dene.
3. Değer-önce hedefle: "burayı kırarsam ne kazanırım?" — auth/para/PII/admin/parser önce.
4. Her tuhaflığa "neden burada?" sor; açıklanamayan detay bir hipotezdir.
5. Tek açık değil ZİNCİR düşün; düşük-etkili bulgu bir halkadır.
6. Soluk sinyali değer + tekrarla tart: yüksek-değer → L3 kaz, değersiz+tek-seferlik → bırak.
7. Araç çıktısını DÖKME, YORUMLA; çıkmazı yeni hipoteze çevir — her duvar bir varsayımı gösterir.
