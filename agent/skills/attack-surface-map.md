---
name: attack-surface-map
description: >
  Düz liste yerine YAPISAL saldırı yüzeyi grafı (surface.json): varlık→subdomain→endpoint→parametre→
  auth durumu→teknoloji→hipotez→bulgu, hepsi ilişkili. Ajan grafı jq ile SEÇİCİ sorgular (tümünü
  bağlama çekmez) → derin muhakeme + düşük token. Recon bunu doldurur, autonomy-loop bunu işler.
---

# 🕸️ ATTACK-SURFACE GRAPH — yüzeyi GÖR, listeyi değil

> **Tek cümle:** Sistem hedefi düz subdomain/endpoint listesi olarak değil, **ilişkili bir graf**
> olarak tutar: hangi parametre hangi endpoint'te, hangi sink'e gidiyor, auth gerekiyor mu, hangi
> teknoloji, hangi hipotez. Ajan "auth endpoint'lerindeki test edilmemiş SQL-aday paramlar" gibi
> sorular sorar — jq ile 20 satır cevap alır, 5000 satır okumaz.

İlişkili: [[autonomy-loop]] (maliyet modeli), [[data-flow-and-mental-model]] (sink muhakemesi),
[[request-economy]], [[access-control-reasoning]], [[target-knowledge-base]].

---

## 1. ŞEMA — surface.json (targets/<hedef>__<tarih>/surface.json)

```json
{
  "target": "acme.com",
  "assets":    [ {"host":"app.acme.com","ip":"","tech":["nginx","laravel"],"waf":"cloudflare",
                  "auth":"jwt","kind":"web","priority":"high"} ],
  "endpoints": [ {"id":"e1","host":"app.acme.com","method":"POST","path":"/api/login",
                  "auth_required":false,"params":["user","pass"],"tech":"laravel",
                  "tested":false,"source":"js"} ],
  "params":    [ {"id":"p1","endpoint":"e1","name":"user","loc":"body","type":"string",
                  "sink_guess":"sql","reflected":false,"tested":false} ],
  "hypotheses":[ {"id":"h1","endpoint":"e1","param":"p1","class":"sqli","score":4.2,
                  "status":"pending"} ],
  "findings":  [ {"id":"f1","class":"idor","endpoint":"e7","status":"proven","req":"cyp_..."} ]
}
```

> Yapı = ilişki. `param.endpoint` → endpoint'e, `endpoint.host` → asset'e bağlanır. Böylece
> "bu host'taki tüm auth-gerektirmeyen SQL-aday paramlar" tek jq ile gelir.

---

## 2. NASIL DOLAR (mekanik — script/araç, model değil)

> **ÖNEMLİ:** Bu graf recon'un YERİNE geçmez. Recon-agent tam derinlikte çalışır (tüm araçlar +
> JS satır-satır analiz + DNS/WAF/cloud). `scripts/surface_build.sh` o derin çıktıyı
> grafa **ingest eden glue**'dur — recon'un ALTINDA, downstream'de. Derinlik düşmez; sadece
> model ham çıktıyı okumaz, damıtılmışı kullanır.


```
- Recon araçları (subfinder/httpx/katana/gau) ham çıktı üretir → bir script bunları surface.json'a
  ekler (jq ile merge, dedup). Model ham listeyi OKUMAZ.
- JS analizi endpoint/param çıkarır → endpoints/params'a eklenir (source:"js").
- Teknoloji parmak izi asset.tech'e yazılır → vuln-* önceliğini belirler.
- sink_guess: param adı + bağlam + tech'ten TAHMİN (→ data-flow-and-mental-model). Model bunu
  param BAŞINA değil, toplu kural olarak verir; script uygular.
```

> Büyük ham çıktılar (binlerce satır) surface.json'a DAMITILIR, sonra atılır (→ özetle-at).

---

## 3. SEÇİCİ SORGU — jq ile dilim al (token'ın kalbi)

Tüm dosyayı bağlama çekme. SADECE gerekeni sor:

```
# Test edilmemiş, auth-gerektirmeyen endpoint'ler (ilk hedefler):
jq -r '.endpoints[] | select(.tested==false and .auth_required==false) | .id+" "+.method+" "+.path' surface.json

# SQL-aday, test edilmemiş paramlar:
jq -r '.params[] | select(.sink_guess=="sql" and .tested==false) | .id+" @"+.endpoint' surface.json

# En yüksek skorlu, beklemede hipotezler (üst 5):
jq -r '.hypotheses | sort_by(-.score) | .[0:5][] | .id+" "+.class+" "+(.score|tostring)' surface.json

# Belirli host'un yüzeyi:
jq -r '.endpoints[] | select(.host=="app.acme.com") | .path' surface.json

# Kanıtlanmış bulgular (zincir için):
jq -c '.findings[] | select(.status=="proven")' surface.json
```

---

## 4. GÜNCELLEME — gözlem grafı zenginleştirir

Her test sonucu grafa İŞLENİR (tek satır jq update veya script):

```
- Endpoint test edildi    → endpoints[id].tested=true
- Param sinyal verdi      → params[id].reflected/signal işaretle
- Hipotez sonuçlandı      → hypotheses[id].status = confirmed|dead
- Yeni yetenek açıldı      → yeni hypotheses ekle (→ chain-attack-builder)
- Bulgu kanıtlandı         → findings'e ekle (req_id ile)
```

> tested bayrakları = dedup'ın grafa gömülü hali (→ [[request-economy]], tested.md ile birlikte).

---

## 5. NEDEN DERİNLİK SAĞLAR

```
- İlişki görünür: "IDOR bulduğum endpoint'in paramı başka 3 endpoint'te de var" → tek tek değil
  topluca test. Cross-endpoint, cross-host muhakeme.
- Önceliklendirme gerçek: yüzeyin tamamına bakıp EN değerli hedefi seçer (kör sıra değil).
- Zincir görünür: findings + endpoints ilişkisi yeni saldırı yollarını ortaya çıkarır.
```

---

## ÖZET — 5 KURAL

1. Hedefi düz liste değil, ilişkili graf (surface.json) olarak tut.
2. Grafı script/araç doldurur; model ham çıktıyı okumaz, damıtılmışı kullanır.
3. jq ile SADECE gereken dilimi sorgula — tüm dosyayı bağlama çekme.
4. Her gözlemi grafa işle (tested/signal/hypothesis/finding) — dedup gömülü.
5. Graf ilişkileri cross-endpoint muhakeme ve zincir için kullanılır = gerçek derinlik.
