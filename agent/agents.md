# 🧠 AGENT4.0 — MERKEZİ MİMARİ DOKÜMANI

> **Sistem:** Otonom Bug Bounty Operasyon Sistemi  
> **İnovasyon:** Anlamsal girdi muhakemesi — gözlemle, anla, hipotez kur, sonra saldır  
> **Dil:** Türkçe (tüm çıktılar, raporlar, analizler)  
> **Versiyon:** 4.0  
> **Tarih:** 15 Haziran 2026  

---

## 1. SİSTEM GENEL BAKIŞ

Agent4.0, **otonom bug bounty operasyonları** için tasarlanmış, çok ajanlı (multi-agent) bir güvenlik test sistemidir. Geleneksel güvenlik tarayıcılarının aksine, körü körüne payload atmaz; her girdiyi **5 katmanlı gözlem protokolü** ile analiz eder, anlamlandırır ve ancak ondan sonra hipotez kurup test eder.

### Temel İnovasyon

```
Geleneksel Araçlar:  Parametre gör → Payload at → Sonuç kontrol et
Agent4.0:            Parametre gör → 5 katman gözlemle → Hipotez kur → Test et → Zincirle
```

Sistem, **10 paralel test ajanını** tek bir orkestratör altında koordine eder. Keşiften raporlamaya kadar tüm süreç `firstphase.md` üzerinden izlenir.

### Sistem Bileşenleri

| Bileşen | Rol |
|---------|-----|
| **Orkestratör** | Merkezi sinir sistemi — iş böler, hipotez üretir, ajanları izler, sonuçları toplar |
| **Recon Agent** | Derin keşif — subdomain, JS analizi, teknoloji stack, tarihsel veri |
| **Fuzzing Agent** | Adaptif keşif motoru — teknolojiye duyarlı endpoint/parametre keşfi |
| **Web Test Agent** | Anlamsal girdi muhakemeli web zaafiyet testi |
| **API Test Agent** | OWASP API Top 10 — semantik yetkilendirme modeli çıkarımlı |
| **Reporter Agent** | PoC doğrulama, CVSS skorlama, profesyonel raporlama |

### Yetenekler (Skills)

| Yetenek | Amaç |
|---------|------|
| **Semantic Input Analyzer** | 5 katmanlı gözlem protokolü — yapısal, zararsız, uç değer, tip ihlali, hipotez |
| **Chain Attack Builder** | 12 zincirleme saldırı kalıbı — bulguları birleştirerek maksimum etki |

---

## 2. MİMARİ DİYAGRAMI

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        KULLANICI / HEDEF GİRİŞİ                          │
│                     "full hedef.com" / "attack api.hedef.com"            │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     🧠 ORKESTRATÖR AJANI                                 │
│                  (ucuz/hızlı model (örnek))                         │
│                                                                          │
│  firstphase.md oku → Mod seç → Recon başlat → Triyaj → Hipotez üret     │
│  → 10 paralel ajan başlat → İzle (heartbeat) → Topla → Reporter'a ver   │
└───────┬─────────────────────────────────────────────────────────┬───────┘
        │                                                         │
        ▼                                                         │
┌───────────────────┐                                             │
│  🕵️ RECON AGENT   │                                             │
│  (Keşif Fazı)     │                                             │
│                   │                                             │
│  • Subdomain      │                                             │
│  • JS Analizi     │                                             │
│  • Teknoloji Stack│                                             │
│  • WAF/CDN Tespit │                                             │
│  • Tarihsel URL   │                                             │
│  • Cloud/Port     │                                             │
│                   │                                             │
│  Çıktı:           │                                             │
│  firstphase.md    │                                             │
└────────┬──────────┘                                             │
         │                                                        │
         │ Recon tamamlandı, triyaj yapıldı                        │
         ▼                                                        │
┌─────────────────────────────────────────────────────────────────┴───────┐
│                     ⚡ 10 PARALEL TEST AJANI                              │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ AGENT-01  │ AGENT-02  │ AGENT-03  │ AGENT-04  │ AGENT-05  │      │   │
│  │ Yüksek    │ API       │ Admin     │ WordPress │ Statik    │      │   │
│  │ riskli    │ hedefler  │ panelleri │ bloglar   │ sayfalar  │      │   │
│  │ hedefler  │           │           │           │           │      │   │
│  ├───────────┼───────────┼───────────┼───────────┼───────────┤      │   │
│  │ AGENT-06  │ AGENT-07  │ AGENT-08  │ AGENT-09  │ AGENT-10  │      │   │
│  │ Orta      │ Staging   │ API       │ Altyapı   │ Diğer     │      │   │
│  │ hedefler  │ ortamları │ gateway   │ Redis/S3   │ subdomain │      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Her ajan: Sistem Anlama → Fuzzing → Web Testi → API Testi → Bulgu      │
│  Durum: firstphase.md (kendi bölümüne yazar, 5dk'da bir heartbeat)      │
└─────────────────────────────────────────────────────────────────┬───────┘
                                                                  │
                                                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     📊 REPORTER AJANI                                    │
│                  (güçlü model (örnek))                           │
│                                                                          │
│  Bulguları topla → PoC doğrula → False positive ele → CVSS hesapla      │
│  → Zincirleme analizi → Profesyonel rapor → firstphase.md'ye yaz        │
└─────────────────────────────────────────────────────────────────────────┘

VERİ AKIŞI: Kullanıcı → Orkestratör → Recon → Triyaj → 10 Paralel → Reporter → Rapor
DURUM YÖNETİMİ: Tüm sistem firstphase.md üzerinden (her ajan kendi bölümüne yazar)
PROXY: Tüm HTTP trafiği Cypture (http://127.0.0.1:8080) üzerinden — istisnasız
MODEL KASKADI: Keşif/Fuzzing = FLASH | Doğrulama/PoC/Rapor = PRO
```

---

## 3. AJAN REFERANS TABLOSU

| Ajan | Dosya Yolu | Rol | Model | Açıklama |
|------|-----------|-----|-------|----------|
| **Cypture Orkestratör** | `.cypture/agents/cypture-orchestrator.md` | Merkezi koordinatör (native task()) | kullanıcı-seçimli (CYP_MODEL) | TEK aracı `task()`. recon → (gate-agent kapısı) → web+api+fuzz paralel → (gate) → reporter sırasıyla uzmanları çağırır. Test/dosya-okuma YAPMAZ; saf delegasyon. Subagent'lar yapılandırılmış modeli miras alır. |
| **Gate Agent** | `.cypture/agents/gate-agent.md` | Operatör kapısı | kullanıcı-seçimli | Faz sonu `/cyp/question.json` yazıp `/cyp/answer.json` bekler; "daha derine in?" kararını (DEEP/STOP) orchestrator'a döndürür. |
| **Recon Agent** | `.cypture/agents/recon-agent.md` | Derin keşif | ucuz/hızlı model | Subdomain keşfi, JS analizi, teknoloji stack, WAF/CDN tespiti, tarihsel URL toplama, cloud depolama keşfi, port tarama. Her bulguyu saldırı yüzeyi perspektifinden yorumlar. |
| **Fuzzing Agent** | `.cypture/agents/fuzzing-agent.md` | Adaptif keşif motoru | ucuz/hızlı model | Tespit edilen teknolojiye göre kelime listesi seçer, yanıt desenlerine göre strateji değiştirir, endpoint/parametre/dizin keşfi yapar. Zaafiyet testi yapmaz. |
| **Web Test Agent** | `.cypture/agents/web-test-agent.md` | Web zaafiyet testi | ucuz/hızlı model | Anlamsal girdi muhakemesi ile çalışır. 5 katmanlı gözlem protokolünü uygular. XSS, SQLi, SSTI, SSRF, LFI, IDOR, XXE, Command Injection ve tüm web zaafiyet kategorilerini test eder. |
| **API Test Agent** | `.cypture/agents/api-test-agent.md` | API güvenlik testi | ucuz/hızlı model | OWASP API Top 10 kapsamında test yapar. Yetkilendirme modelini çıkarır, BOLA/BFLA/Mass Assignment testlerini bağlam farkındalığıyla gerçekleştirir. GraphQL özel testleri içerir. |
| **Reporter Agent** | `.cypture/agents/reporter-agent.md` | Bulgu doğrulama ve raporlama | güçlü model | Tüm bulguları bizzat yeniden üretir, false positive'leri eler, CVSS 3.1 skorlaması yapar, zincirleme analizi gerçekleştirir ve profesyonel Türkçe rapor üretir. |

---

## 4. YETENEK REFERANS TABLOSU

### 4.1 Çekirdek Disiplin Modülleri (ZORUNLU — tüm ajanlar)

> Bu 5 modül sistemin yeni çekirdeğidir. Zayıf modelde bile yüksek kalite üretmek için
> deterministik kapılar getirir. Her ajan dosyasının başına **ÇEKİRDEK SÖZLEŞME** olarak
> enjekte edilmiştir; derin referans bu modüllerdedir. Runtime ve model bağımsızdır.

| Modül | Dosya Yolu | Amaç |
|-------|-----------|------|
| **Core Contract** | `skills/core-contract.md` | 12 değiştirilemez kuralın tek-sayfa özeti. Her ajanın başında bulunur, 4 modüle bağlanır. |
| **Cypture MCP Contract** | `skills/engine-mcp-contract.md` | Tüm trafiğin Cypture MCP ile gitmesi: araç adı keşfi/fallback, ham HTTP şablonu, scope, session/cookie, `create_finding`, request_id loglama. curl yasağı. |
| **Evidence Discipline** | `skills/evidence-discipline.md` | Anti-halüsinasyon: her iddia için request_id + gözlemlenmiş somut fark. Güven seviyeleri (KANIT/GÖZLEM/HİPOTEZ/TAHMİN), üç soru kapısı, "bilmiyorsan bilmiyorum de". |
| **Baseline & Signal** | `skills/baseline-and-signal.md` | Anti-brute-force: bulgu için baseline'dan ölçülebilir sapma + tekrar zorunlu. Sinyal-gürültü ayrımı, insan-benzeri akıllı test sırası, WAF farkındalığı. |
| **Request Economy** | `skills/request-economy.md` | Token/istek ekonomisi: aynı isteği tekrar atma yasağı, `bodyLimit`/metadata-only, dedup, durma kriterleri, kısa çıktı disiplini. |

### 4.2 Saldırı Tekniği Yetenekleri

| Yetenek | Dosya Yolu | Amaç |
|---------|-----------|------|
| **Semantic Input Analyzer** | `skills/semantic-input-analyzer.md` | Ajanlara kör payload atmak yerine 5 katmanlı gözlem protokolü uygulamayı öğretir: (1) Yapısal Gözlem, (2) Zararsız Değer Gözlemi, (3) Uç Değer Gözlemi, (4) Tip İhlali Gözlemi, (5) Hipotez Üretimi. Ayrıca yanıt karşılaştırma, zamanlama analizi ve bağlam tespit protokollerini içerir. |
| **Chain Attack Builder** | `skills/chain-attack-builder.md` | Bulguları zincirleyerek maksimum etki elde etmeyi öğretir. 12 yaygın zincir kalıbı (XSS→ATO, SQLi→Credential Dump, SSRF→Cloud Takeover, LFI+Log Poisoning→RCE, IDOR+Mass Assignment, vb.), cross-agent zincirleme koordinasyonu ve zincir kırılma noktaları için alternatif yollar içerir. |

### 4.3 Muhakeme Yetenekleri (İNSAN GİBİ DÜŞÜNME — yeni)

> Bunlar sistemin "zekası"dır. Zayıf modelin en çok eksik olduğu yer: tek input'a bakıp payload
> atmak yerine verinin yolculuğunu kafada kurmak, ısrar etmek, iş mantığını ve yetkiyi akıl yürütmek.

| Yetenek | Dosya Yolu | Amaç |
|---------|-----------|------|
| **Data-Flow & Mental Model** | `skills/data-flow-and-mental-model.md` | Her girdi için "ne alıyor? ne yapıyor? nereye gönderiyor? sonuç nerede çıkıyor?" — source→sink izleme, etkinin gecikmeli/çapraz/blind çıkışı, tüm uygulamanın zihinsel modeli. |
| **Attacker Mindset & Persistence** | `skills/attacker-mindset-and-persistence.md` | "Çalışmadı" yerine "neden çalışmadı"; akıllı varyasyon (encoding/bağlam/sink), erken pes etmeme vs kör brute dengesi, dürüst tükenme kontrol listesi. |
| **Business Logic Reasoning** | `skills/business-logic-reasoning.md` | Brute edilemeyen iş mantığı açıkları: fiyat/negatif/akış atlama/durum/replay/kupon/limit, race condition; geliştirici varsayımlarını çıkarıp ihlal. |
| **Access-Control Reasoning** | `skills/access-control-reasoning.md` | IDOR/BOLA/BFLA/Mass Assignment'ı zekice: yetki modeli çıkarımı, iki kimlik (iki sessionId), ID formatı çözümü, kör enum yerine hedefli ihlal. |
| **Depth Calibration** ⭐ | `skills/depth-calibration.md` | Test fazının karar beyni: nereye ZORUNLU derine in (değer/sinyal tetikleyicisi → L3+), nereye inme (L0/L1). "Derine inmesi gerekeni yüzeysel geçme" hatasını bitirir. Full scan = her yere DOĞRU derinlik. |

### 4.4 Açık Sınıfı Playbook'ları (talep üzerine yüklenir — token-ucuz)

> 23 odaklı, karar-merkezli playbook. Her biri: ne zaman uygulanır (sink/bağlam) · insan muhakemesi ·
> teşhis prob'u · sinyal vs gürültü · doğrulama kapısı · varyasyon/bypass · false-positive tuzakları ·
> durma kriteri. Ajan ilgili sınıfı test ederken SADECE o dosyayı yükler (devasa payload listesi değil,
> karar mantığı). Tümü çekirdek disipline ([[evidence-discipline]] vb.) bağlıdır.

| Aile | Playbook'lar (`skills/vuln-*.md`) |
|------|----------------------------------|
| **Injection** | `vuln-sqli` · `vuln-nosqli` · `vuln-command-injection` · `vuln-ssti` · `vuln-xxe` · `vuln-lfi-path-traversal` · `vuln-ssrf` · `vuln-crlf-header-injection` |
| **Client / Tarayıcı** | `vuln-xss` · `vuln-cors-misconfig` · `vuln-csrf` · `vuln-open-redirect` · `vuln-clickjacking` · `vuln-cache-poisoning-deception` · `vuln-prototype-pollution` · `vuln-http-request-smuggling` |
| **Kimlik / Oturum** | `vuln-jwt-attacks` · `vuln-oauth-attacks` · `vuln-auth-session` |
| **Dosya / Veri / API** | `vuln-file-upload` · `vuln-deserialization` · `vuln-graphql` · `vuln-rate-limit-resource` |

> **Not:** IDOR/BOLA/BFLA/Mass Assignment ve iş mantığı/race, ayrı playbook yerine muhakeme
> yetenekleriyle (`access-control-reasoning`, `business-logic-reasoning`) ele alınır — bu sınıflar
> payload değil akıl yürütme gerektirir.

> **Blind açıklar:** Görünür yanıtı olmayan (Blind SSRF/XSS/SQLi/XXE/RCE/Deserialization) sınıflar
> `skills/out-of-band-testing.md` ile kanıtlanır — **Cypture QuickSSRF** eklentisine gelen DNS/HTTP
> geri-çağrısı yakalanır. "Yanıtta yok" ≠ "açık yok"; etki dışarı taşınıp kanıtlanır.

### 4.5 Operasyonel Yetenekler

| Yetenek | Dosya Yolu | Amaç |
|---------|-----------|------|
| **Auth & Session Handling** | `skills/auth-session-handling.md` | Authenticated test: login akışını izleme, token/cookie'yi Cypture sessionId ile taşıma, yenileme, IDOR/BFLA için iki kimlik, CSRF token akışı. Login arkası yüzey buradan açılır. |
| **Out-of-Band Testing** | `skills/out-of-band-testing.md` | Blind açık kanıtı — Cypture QuickSSRF ile DNS/HTTP geri-çağrı yakalama, benzersiz işaretçi, negatif kontrol. |
| **Run Metrics & Self-Review** | `skills/run-metrics-and-selfreview.md` | Koşum sonu metrik (istek/tekrar/şüpheli/kanıt + istek-başına-bulgu), rapor öncesi false-positive öz-denetim, kapsam tamlık kontrolü. Token ve kaliteyi görünür kılar. |

### 4.6 Otonom Yığın — "isim ver, gerisini yap" (DERİN ama UCUZ)

> **Maliyet ilkesi:** mekanik işi (scope çekme, parse, dedup, skorlama, graf) **script/jq yapar**;
> model sadece KARAR verir. Bu, derin otonomluğu token-ucuz kılar. Detay: `skills/autonomy-loop.md`.

| Yetenek | Dosya Yolu | Amaç |
|---------|-----------|------|
| **Scope Ingestion** | `skills/scope-ingestion.md` + `scripts/scope_fetch.sh` | `bounty h1:handle` → scope'u platformdan/public veri setinden DETERMINISTIK çek → scope.md + Cypture scope. Model JSON parse etmez. |
| **Attack-Surface Map** | `skills/attack-surface-map.md` | Yapısal yüzey grafı (`surface.json`): varlık→endpoint→param→sink→hipotez→bulgu. jq ile seçici sorgu (tümünü okumaz). Gerçek derinlik. |
| **Autonomy Loop** | `skills/autonomy-loop.md` | Plan→uygula→gözlemle→replan; öncelik-skorlu hipotez backlog; bütçe kapısı; "derin ama ucuz" 7 kaldıraçlı maliyet modeli. Orkestratörün motoru. |

---

## 5. ANLAMSAL MUHAKEME PRENSİBİ (SEMANTİK REASONİNG)

Sistemin temel felsefesi, tüm ajana ve yeteneğe işlenmiş olan şu prensiptir:

```
GÖZLEMLE → ANLA → HİPOTEZ KUR → TEST ET → BELGELE
```

### Neden?

Geleneksel güvenlik tarayıcıları şöyle çalışır:
- `?q=` parametresi gör → XSS payload listesini sırayla dene
- `?id=` parametresi gör → SQLi payload listesini sırayla dene
- Sonuç: %95 gürültü, atlanan bağlama özgü açıklar, kaçan zincirleme fırsatları

Agent4.0 şöyle çalışır:
- `?q=` parametresi gör → önce ne işe yaradığını anla (arama mı, filtre mi, autocomplete mi?)
- Normal değer gönder → baseline oluştur (yanıt süresi, boyutu, içeriği)
- Uç değerler gönder → hata mesajlarından teknoloji yığınını tespit et
- Tip ihlali yap → backend dilini, framework'ü, veritabanını kesinleştir
- **Ancak ondan sonra** hipotez kur ve test et

### 5 Katmanlı Gözlem Protokolü (Özet)

| Katman | Amaç | Ne Yapılır |
|--------|------|-----------|
| **Katman 1** — Yapısal Gözlem | Girdinin kimliğini anla | HTML tipi, DOM konumu, doğrulama kuralları, JS olay işleyicileri belgelenir. |
| **Katman 2** — Zararsız Değer | Baseline oluştur | Normal değer gönderilir; yanıt süresi, boyutu, yansıma bağlamı, kodlama biçimi kaydedilir. |
| **Katman 3** — Uç Değer | Sınırları haritala | Boş, çok uzun, özel karakter, Unicode, null byte gönderilir; hata formatı ve WAF davranışı gözlemlenir. |
| **Katman 4** — Tip İhlali | Teknoloji yığınını tespit et | Sayı yerine metin, e-posta yerine URL gönderilir; hata mesajlarından dil/framework/veritabanı belirlenir. |
| **Katman 5** — Hipotez Üretimi | Test stratejisi belirle | Tüm gözlemler birleştirilir, mümkün açık türleri öncelik sırasına konur, test planı oluşturulur. |

---

## 6. MOD SİSTEMİ

Orkestratör 5 farklı modda çalışabilir. Mod, `firstphase.md` üzerinden belirlenir.

| Mod | Komut Örneği | Akış | Süre | Ajan Sayısı | Açıklama |
|-----|-------------|------|------|-------------|----------|
| **full** | `full hedef.com` | INIT → RECON → SPLIT → 10 PARALEL → COLLECT → REPORT | 90-180 dk | 12 | Tam kapsamlı operasyon. Sıfırdan keşif, tüm test kategorileri. |
| **attack** | `attack api.hedef.com` | INIT → 2dk HIZLI RECON → SPLIT → 10 PARALEL → COLLECT → REPORT | 30-90 dk | 11 | Subdomainler biliniyor, doğrudan saldırı. Keşif atlanır, sadece 2 dakikalık hızlı header/robots.txt kontrolü yapılır. |
| **web** | `web hedef.com` | INIT → SPLIT → 10 PARALEL (web-only) → COLLECT → REPORT | 20-60 dk | 11 | Sadece web zaafiyet kategorileri. API testleri yapılmaz. |
| **api** | `api api.hedef.com` | INIT → SPLIT → 10 PARALEL (api-only) → COLLECT → REPORT | 20-60 dk | 11 | Sadece API zaafiyet kategorileri. Web testleri yapılmaz. |
| **recon** | `recon hedef.com` | INIT → RECON → DONE | 10-30 dk | 1 | Sadece keşif. Hiçbir saldırı testi yapılmaz. |

### Durum Makinesi

```
INIT → RECON_RUNNING → RECON_COMPLETE → SPLITTING → AGENTS_RUNNING → COLLECTING → REPORTING → DONE
                                       ↑ (attack/web/api: recon atlanır, direkt SPLITTING)
```

Her durum geçişi `firstphase.md` dosyasına yazılır. Timeout'lar: Recon 30 dk, tek ajan 45 dk, tüm ajanlar 90 dk.

---

## 7. HIZLI BAŞLANGIÇ

### Başlatma Komutları

```
full hedef.com              → Tam kapsamlı operasyon (keşif + tüm testler)
attack api.hedef.com        → Doğrudan saldırı (subdomainler biliniyor)
web hedef.com               → Sadece web testleri
api api.hedef.com           → Sadece API testleri
recon hedef.com             → Sadece keşif
```

### Ön Koşullar

1. **Cypture** çalışıyor ve **Cypture MCP araçları** erişilebilir olmalıdır (proxy: `http://127.0.0.1:8080`). Araç adı/öneki operasyon başında keşfedilir.
2. **Model** herhangi bir yetenekli model olabilir — sistem model-bağımsızdır. Kademe (ucuz keşif / güçlü doğrulama) bir maliyet optimizasyonudur, zorunluluk değil. Zayıf modelde kapılar otomatik sıkılaşır.
3. **firstphase.md** dosyası yazılabilir durumda olmalıdır.
4. Hedef domain için test izni alınmış olmalıdır.

### Çalışma Dizini

```
<proje-kökü>/                    → Proje kökü
<proje-kökü>/firstphase.md       → Durum ve hafıza dosyası
```

---

## 8. DEĞİŞTİRİLEMEZ KURALLAR

Bu kurallar sistemin bütünlüğü için zorunludur. Hiçbir ajan veya operatör tarafından ihlal edilemez.

| # | Kural | Gerekçe |
|---|-------|---------|
| **1** | **Önce gözlemle, sonra saldır.** | Kör payload atmak gürültü üretir ve bağlama özgü açıkları kaçırır. |
| **2** | **Her test Faz-0 ile başlar.** | 5 katmanlı gözlem protokolü uygulanmadan hiçbir payload gönderilmez. |
| **3** | **Cypture MCP istisnasızdır.** | Hedefe giden TÜM HTTP trafiği Cypture MCP `send_request` aracıyla gider (curl değil). Araç adı/öneki operasyon başında bir kez keşfedilir (`skills/engine-mcp-contract.md`). İzlenebilirlik, tekrarlanabilirlik ve token tasarrufu için zorunludur. |
| **4** | **Sistem model-bağımsızdır.** | Hangi modelle çalışırsa çalışsın kalite, modele DEĞİL deterministik kapılara (kanıt/baseline/ekonomi) dayanır. Model değişirse operasyon DURMAZ; daha zayıf model algılanırsa kapılar SIKILAŞIR (emin değilsen "ŞÜPHELİ"/"BİLİNMİYOR"). Modele güvenip disiplini gevşetmek yasaktır. |
| **4b** | **Kanıtsız iddia yok (anti-halüsinasyon).** | Gözlemlenmeyen hiçbir şey iddia edilmez. Her bulgu request_id + baseline'dan ölçülebilir, tekrarlanmış sapma gerektirir (`skills/evidence-discipline.md`). |
| **4c** | **Token/istek ekonomisi.** | Aynı istek iki kez atılmaz, büyük gövde bağlama doldurulmaz, kör wordlist tüketilmez. Sinyal yoksa kapatılır (`skills/request-economy.md`). |
| **5** | **Durum güncellenmeden ilerlenmez.** | Her adımda `firstphase.md` güncellenir. Durum bilinmeden karar verilmez. |
| **6** | **Ajanlar sadece kendi bölümüne yazar.** | `firstphase.md` çakışması önlenir. Hiçbir ajan başka bir ajanın bölümüne yazamaz. |
| **7** | **Keşif ajanı saldırmaz, test ajanı keşif yapmaz.** | Görev ayrımı nettir. Recon Agent zaafiyet testi yapmaz; Web/API test ajanları subdomain keşfi yapmaz. |
| **8** | **Erken biten ajan boş beklemez.** | Work stealing: Tamamlanan ajana, yavaş ajanın kalan işi aktarılır. |
| **9** | **Kritik bulgu cross-agent yayınlanır.** | Bir ajan JWT secret bulursa, tüm ajanlar bu secret ile token forge etmeyi dener. |
| **10** | **PoC'siz bulgu raporlanmaz.** | Reporter Agent, her bulguyu bizzat yeniden üretir. Doğrulanamayan bulgu rapora girmez. |

---

## 8.5 WORKSPACE MODELİ (per-hedef izolasyon)

> Kök `firstphase.md` artık bir **ŞABLONDUR** — asla yazılmaz. Her operasyon kendi izole klasöründe çalışır.
> Bu, hedef verilerinin karışmasını önler, şablonu temiz tutar ve gerçek angajman verisinin GitHub'a
> sızmasını engeller (`targets/` `.gitignore`'dadır). (izole hedef klasörü + scope koruması).

```
agent4.0/
├── firstphase.md                 ← PRİSTİN ŞABLON (sadece kopyalanır, asla yazılmaz)
├── templates/
│   ├── scope.md                  ← kapsam/izin şablonu
│   └── report.md                 ← rapor şablonu
└── targets/                      ← [.gitignore — gerçek angajman verisi]
    └── <hedef>__<tarih>/
        ├── firstphase.md         ← bu hedefin CANLI durumu (şablon kopyası)
        ├── scope.md              ← in/out kapsam + test izni
        ├── tested.md             ← çapraz-koşum dedup defteri (aynı isteği tekrarlama)
        ├── recon/                ← subdomains, live_hosts, js_files, recon çıktıları
        ├── findings/             ← bulgu kanıtları + PoC
        └── report.md             ← final rapor
```

**Orkestratör ADIM 0 (bootstrap):** hedef normalize → resume kontrolü → klasör + şablon kopyası →
scope.md doldur → Cypture scope kur → araç adı keşfi. Ondan sonra "firstphase.md" = aktif kopyadır.

---

## 9. DOSYA HARİTASI

```
<proje-kökü>/
├── agents.md                              ← BU DOSYA — merkezi mimari dokümanı
├── firstphase.md                          ← Durum ve hafıza dosyası (tüm ajanlar buraya yazar)
│
├── .cypture/
│   ├── cypture.json                      ← Proje yapılandırması (modeller, ajan tanımları)
│   └── agents/
│       ├── cypture-orchestrator.md        ← 🧠 Cypture Orkestratör — native task() koordinatör
│       ├── gate-agent.md                  ← 🚪 Gate Agent — operatör kapısı (daha derine?)
│       ├── recon-agent.md                 ← 🕵️ Recon Agent — derin keşif
│       ├── fuzzing-agent.md               ← 🔍 Fuzzing Agent — adaptif endpoint keşfi
│       ├── web-test-agent.md              ← 🌐 Web Test Agent — anlamsal girdi muhakemeli
│       ├── api-test-agent.md              ← 📡 API Test Agent — OWASP Top 10, GraphQL
│       └── reporter-agent.md              ← 📊 Reporter Agent — PoC doğrulama, CVSS, rapor
│
├── skills/
    ├── semantic-input-analyzer.md         ← 🧩 5 katmanlı gözlem protokolü
    └── chain-attack-builder.md            ← 🔗 12 zincirleme saldırı kalıbı
```

### Dosya Sorumluluk Matrisi

| Dosya | Kim Okur? | Kim Yazar? |
|-------|----------|-----------|
| `firstphase.md` | Tüm ajanlar | Tüm ajanlar (her biri sadece kendi bölümüne) |
| `agents.md` | İnsan operatör, yeni ajanlar | Sistem mimarı |
| `.cypture/cypture.json` | Cypture runtime | Sistem mimarı |
| `.cypture/agents/*.md` | İlgili ajan (kendi dosyası) | Sistem mimarı |
| `skills/*.md` | Tüm test ajanları (referans) | Sistem mimarı |

### Model Kullanım Matrisi

> **Not:** Model isimleri ÖRNEKTİR. Sistem model-bağımsızdır; kademe bir maliyet optimizasyonudur.
> "UCUZ/HIZLI MODEL" ve "GÜÇLÜ MODEL" yerine elindeki herhangi iki kademeyi koyabilirsin
> (ya da tek model kullanabilirsin). Kalite modelden değil, çekirdek kapılardan gelir.

| Görev Tipi | Kademe (örnek model) | Gerekçe |
|-----------|-------|---------|
| Keşif (Recon) | UCUZ/HIZLI (örn. ucuz/hızlı model) | Yüksek hacimli istek, düşük analiz derinliği |
| Fuzzing | UCUZ/HIZLI | Mekanik, tekrarlı, pattern-match |
| Rutin web/API testleri | UCUZ/HIZLI | Checklist bazlı, hızlı tarama |
| Şüpheli yanıt analizi | UCUZ → GÜÇLÜ | Ucuz model sinyal bulursa güçlü modele yükselt |
| PoC oluşturma | GÜÇLÜ (örn. güçlü model) | Kesin sonuç, sıfır hata toleransı |
| Zincirleme exploit | GÜÇLÜ | Çok adımlı, her adım kritik |
| CVSS hesaplama | GÜÇLÜ | Hassas skorlama, standart uyumluluğu |
| Rapor yazımı | GÜÇLÜ | Profesyonel format, müşteriye sunulacak |

### Model Yükseltme Tetikleyicileri

Flash → Pro geçişi şu durumlarda yapılır:
- Time-based SQLi'de 3+ saniye gecikme
- SSTI tespiti (`{{7*7}}` → 49)
- Başarılı dosya okuma (LFI ile `/etc/passwd`)
- SSRF ile cloud metadata yanıtı
- Deserialization kabulü (Java/Pickle)
- Komut enjeksiyonu (`; id` çalıştı)

---

## 10. İLETİŞİM PROTOKOLÜ

### Ajanlar Arası İletişim

```
Orkestratör → Ajan:      Görev + Hipotez + Subdomain listesi
Ajan → Orkestratör:      firstphase.md (kendi bölümüne yazar)
Ajan → Orkestratör:      Kritik bulgu anında bildirimi
Orkestratör → Tüm Ajanlar: Cross-agent bildirim (kritik bulgu yayını)
Orkestratör → Reporter:   Toplama raporu
```

### Heartbeat Protokolü

- Her ajan **5 dakikada bir** `firstphase.md` dosyasındaki kendi bölümünde `Son güncelleme: [timestamp]` satırını günceller.
- Orkestratör **3 dakikada bir** tüm ajanların heartbeat'ini kontrol eder.
- 15 dakika sessiz kalan ajan **ölü** kabul edilir, işi diğer ajanlara dağıtılır.

### Cross-Agent Bildirim Formatı

Bir ajan kritik bulgu bulduğunda, orkestratör `firstphase.md` dosyasına `## 🔔 CROSS-AGENT BİLDİRİM` bölümüne yazar. Tüm ajanlar bu bölümü okuyup kendi subdomainlerinde ilgili testi tekrarlar.

---

## 11. KALİTE KAPILARI

Orkestratör hiçbir aşamayı kontrol etmeden geçmez. 7 kalite kapısı:

| Kapı | Aşama | Kontrol Edilen |
|------|-------|---------------|
| K1 | Recon öncesi | Hedef belirlendi mi? Mod seçildi mi? Cypture çalışıyor mu? |
| K2 | Recon sonrası | `live_hosts.txt` oluştu mu? JS tablosu dolu mu? |
| K3 | Triyaj sonrası | Her subdomain profillendi mi? Hipotez üretildi mi? |
| K4 | Ajan başlatma öncesi | En az 1 ajan aktif mi? Her ajana hipotez verildi mi? |
| K5 | Bulgu toplama öncesi | Tüm ajanlar tamamlandı mı? Eksik ajan belgelendi mi? |
| K6 | Reporter öncesi | Deduplikasyon yapıldı mı? Zincirleme analizi tamam mı? |
| K7 | Operasyon sonu | Rapor yazıldı mı? Kullanıcıya özet sunuldu mu? |

---

## 12. TEKNİK REFERANS

### Proxy Yapılandırması

```
HTTP_PROXY:  http://127.0.0.1:8080
HTTPS_PROXY: http://127.0.0.1:8080
Tüm araçlar: -x http://127.0.0.1:8080 veya --proxy http://127.0.0.1:8080
```

### Çalışma Dizinleri

```
<proje-kökü>/                    → Proje kökü
<proje-kökü>/firstphase.md       → Durum dosyası
<proje-kökü>/subdomains_final.txt → Keşif çıktısı
<proje-kökü>/live_hosts.txt      → Canlı subdomain listesi
<proje-kökü>/js_files/           → İndirilen JS dosyaları
<proje-kökü>/recon_output/       → Recon çıktıları
/tmp/fuzzing/                              → Fuzzing geçici çıktıları
```

---

## 13. KISITLAMALAR VE SINIRLAR

| Sınır | Değer | Açıklama |
|-------|-------|----------|
| Maksimum paralel ajan | 10 | Aynı anda en fazla 10 test ajanı |
| Recon timeout | 30 dk | Keşif aşaması maksimum süresi |
| Tek ajan timeout | 45 dk | Bir test ajanının maksimum çalışma süresi |
| Global timeout | 90 dk | Tüm test ajanlarının toplam maksimum süresi |
| Heartbeat aralığı | 5 dk | Ajanların durum güncelleme sıklığı |
| Orkestratör kontrol aralığı | 3 dk | Orkestratörün heartbeat kontrol sıklığı |
| Maksimum recon denemesi | 3 | Recon başarısız olursa tekrar sayısı |
| Work stealing eşiği | %20 ilerleme farkı | Yavaş ajandan iş çalma tetikleyicisi |

### Yasaklı Eylemler

- Rate limiting ihlali yapacak agresif tarama
- Üretim ortamında yıkıcı test (DROP TABLE, DELETE, shutdown)
- Hedef dışı sistemlere erişim
- Bulunan credential'ların yetkisiz kullanımı
- DoS oluşturacak istek hacmi
- Kişisel verilerin dışarı çıkarılması (sadece PoC için minimal örnek)

---

> **"Keşif savaşın yarısıdır. Derin keşif, savaşın tamamıdır."**
>
> Bu sistem, test ajanlarına savaşacak bir şey bırakmamak üzere tasarlanmıştır.
> Her şeyi bul, her şeyi analiz et, her şeyi belgele.
> Test ajanları sadece onaylamak ve PoC üretmek için kalsın.
