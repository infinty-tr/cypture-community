# 📊 GÜVENLİK TEST RAPORU — [hedef]

> `targets/<hedef>__<tarih>/report.md`. Reporter agent doldurur. Sadece KANIT seviyesindeki,
> yeniden üretilmiş bulgular girer (`skills/evidence-discipline.md`). PoC'siz bulgu rapora girmez.

## Yönetici Özeti
- **Hedef:** [domain] | **Tarih:** [aralık] | **Mod:** [full/attack/web/api]
- **Kapsam:** [özet] | **Test edilen yüzey:** [N subdomain, M endpoint]
- **Bulgu özeti:** 🔴 Kritik: [n] · 🟠 Yüksek: [n] · 🟡 Orta: [n] · 🟢 Düşük: [n] · ℹ️ Info: [n]
- **En kritik risk:** [tek cümle]

---

## Bulgular

### 🔴 BULGU #1 — [Açık Türü] — [Severity]
- **Konum:** [tam URL] | **Method:** [GET/POST] | **Parametre:** [ad/konum]
- **CVSS 3.1:** [skor] — `[vektör]`
- **Açıklama:** [teknik detay, 3-5 cümle — verinin akışı: ne alıyor/nereye/sonuç nerede]
- **Kanıt:**
  - Baseline: `req_AAAA` → [kod, ms, boyut]
  - Tetikleyici: `req_BBBB` → `[payload]` → [kod, ms, boyut, FARK]
  - Tekrar: [N kez, tutarlı] | Cypture finding: `[id]`
- **PoC (ham istek):**
  ```
  [Cypture send_request raw — gerçek istek]
  ```
- **Etki:** [iş/veri/sistem etkisi] | **Zincir:** [diğer bulgularla birleşim]
- **Çözüm:** [spesifik, uygulanabilir düzeltme]

---

## Zincirleme Senaryoları
> Tek başına düşük etkili bulgular birleşince (`skills/chain-attack-builder.md`).
- [Zincir 1: A + B → kritik etki — adımlar + kanıt]

## Kapsanan / Kapsanmayan
- **Test edildi:** [kategoriler/subdomainler]
- **Atlandı (sebebiyle):** [scope dışı / teknoloji uymadı / SKIP notları]
- **Şüpheli (doğrulanamadı):** [ileride dönülecekler]

## Metodoloji Notu
Gözlem → veri akışı → hipotez → test → kanıt → zincir. Tüm trafik Cypture üzerinden loglandı;
her bulgu request_id ile doğrulanabilir ve yeniden üretilebilir.
