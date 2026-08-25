# 🧠 CYPTURE — Otonom Bug Bounty Avcı Sistemi

> **Tek satır vaat:** Kullanıcı yalnız **`pentest <hedef>`** yazar. Sistem gerisini kendi çıkarır — scope, derinlik,
> test sınıfları, kimlikler, ne zaman bittiği. Gerçek, olağanüstü yetenekli bir insan avcı gibi **düşünür**:
> hedefin teorisini kurar, geliştiricinin kafasına girer, "bu tuhaf" diyebilir, tutarsızlıkları görür, teorisini
> çürütmeye çalışır, geçmişten öğrenir.
>
> **Çekirdek felsefe:** Kararları deterministik script'ler verir; model yalnız uygular. Bu sayede çıktı kalitesi
> büyük ölçüde modelden bağımsız kalır. Zaman bir durma kriteri DEĞİL — **derinlik** ve
> **kanıtla tükenme** öyle.

Bu doküman sistemin uçtan uca yapısını ve nasıl çalıştığını ayrıntısıyla anlatır.

---

## 0. ALTI TASARIM HEDEFİ

1. **Sıfır-instruction otonomi** — kullanıcı tek komut yazar; gerisi otomatik.
2. **Modelden bağımsız kalite** — hangi model verilirse çıktı tutarlı kalır; kalite deterministik kapılardan gelir.
3. **Görülmeyeni görmek** — checklist değil, gerçek hacker zihni (mental model, anomali, zincir).
4. **Mutlak doğruluk** — sıfır false-positive. Her bulgu: aşılan sınır + Cypture request_id + ölçülü fark.
5. **Açık bulana kadar durmama** — "açık yok" YALNIZCA yüzey KANITLA tükendiğinde geçerli.
6. **Zaman durma kriteri değil — derinlik öyle.**

---

## 1. İKİ KATMANLI MİMARİ

```
┌─────────────────────────────────────────────────────────────────────┐
│  MODEL KATMANI (cypture-agent/Claude ajanları)  —  UYGULAYICI             │
│   cypture-orchestrator (baş yönetim) + recon · fuzzing · web-test ·  │
│   api-test · reporter                                                │
│   • Cypture MCP ile HTTP atar (tek yol)  • payload/zincir muhakemesi   │
│   • script'leri çağırır, KISA çıktılarını okur, dediğini uygular     │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ okur / yazar (tek makine durumu)
┌───────────────────────────────▼─────────────────────────────────────┐
│  DETERMİNİSTİK KATMAN (45 bash+jq script)  —  BEYİN + HAKEM           │
│   karar · biliş (teori/anomali/boşluk/inanç) · kapsama · kanıt kapısı│
│   · sinyal · öğrenme çarkı · dayanıklılık                            │
│   surface.json = TEK MAKİNE DURUMU                                   │
└──────────────────────────────────────────────────────────────────────┘
```

**Neden?** Bir karar (bitti mi? gerçek IDOR mu? hangi açı? hangi model?) script'te deterministik verilirse, model
ne kadar zayıf olursa olsun sonuç aynı kalır. Model "yaratıcı" işi yapar (payload, zincir, yansıma yorumu);
"hakem" işini hiç yapmaz. Bir `loop-enforcer.js` plugin'i, oturum boşa düşünce kararı zorlar — sistem erken duramaz.

---

## 2. TEK DURUM: `surface.json` (state spine)

Tüm script'ler bunu okur/yazar; karar buradan çıkar. `firstphase.md` yalnız insan-okunur kanıt günlüğü (script
parse etmez). Atomik yazım: `jq ... > tmp && mv`. Şema: `skills/surface-schema.md`.

```jsonc
{
  "target": "privy.io",
  "run":      { budget_max, budget_spent, stop_reason, throttle, unreachable,
                oob_domain, model_health{}, kb_confirmed_tech[] },
  "theory":   { purpose, value_assets[], actors[], trust_boundaries[]{name,weight,control},
                critical_flows[]{name,assumptions[]}, developer_profile, open_questions[]{q,boundary,impact,state} },
  "beliefs":  [ {claim, confidence(0-1), supports[], contradicts[], status} ],
  "assets":   [ {host, tech[], priority, depth_achieved(L0-L4), test_classes{}, applicable_classes[],
                identities[], assigned_to, assigned_at, budget_spent} ],
  "endpoints":[ {id, host, method, path, auth_required, params[], tested, depth_achieved} ],
  "params":   [ {id, endpoint, name, loc, reflected, tested} ],
  "hypotheses":[ {id, host, param, class, angle, intent, impact, state, priority_boost} ],
  "findings": [ {type, host, boundary, impact, baseline_req, deviation_req, severity, signal_ref, state} ],
  "agents":   [ {task_id, hosts[], assigned_at, last_heartbeat, status} ],
  "oob_canaries":[ {token, fqdn, host, class, injected, confirmed, poll_count} ],
  "kb_dead_ends":[ ... ]
}
```

- **Derinlik L0–L4**: `mark_from_engine.sh` Cypture trafiğinden KANITLA hesaplar (model beyanı değil).
- **finding.state**: `candidate → validated → reported | refuted`. Yalnız `validated` rapora girer.
- **Tamamlanma (Goal 5)**: bir host "tükendi" ⇔ dikkatlice incelendi + `theory.open_questions` cevaplandı +
  mantık-hipotezleri & inançlar tükendi + sinyaller çözüldü + L3+. **Sınıf-matrisi DEĞİL** (checklist kaldırıldı).

---

## 3. KARAR BEYNİ: `decide_next.sh`

Sistemin **tek karar kaynağı**. Model her tur, plugin idle'da, pano hep bunu çağırır → tek karar, çelişki yok.
Watchdog + model kademesi + skorlu-seçim içerir. Çıktı: tek bir `DECISION:` satırı.

```
1 unreachable?                          → STOP UNREACHABLE
2 healthy model yok?                    → STOP NO_WORKING_MODEL   (hepsi geçici soğuyorsa → CONTINUE-WAIT)
3 budget_spent ≥ budget_max?            → STOP BUDGET_EXHAUSTED
4 watchdog: ölü/asılı ajan kirasını serbest bırak (host re-queue)
5 score_hypotheses.sh → EN YÜKSEK puanlı açık işi seç:
     belief_test (inanç çürüt) · chain_opp · pending_signal · oob_hit · open_hypothesis(niyet/anomali/gap) ·
     host_deepen(L3'e) · host_untested(yeni subdomain incele)
   → CONTINUE-* (koku/değer önce; kör genişlik değil)
6 hiç açık iş yok AMA theory.open_questions açık? → CONTINUE-NEW-HYPOTHESIS (önce ANLA)
7 her şey tükendi:  validated>0 → STOP VULN_FOUND_AND_EXHAUSTED  ;  else → STOP EXHAUSTED_NO_VULN
```

**Skor = Impact × Probability × Accessibility / Cost** + iş-etkisi çarpanları (asset duyarlılığı, sınır ağırlığı,
kritik-akış, freshness). Aynı IDOR `/transfer`'de `/avatar`'dakinden çok daha yüksek puan alır.

---

## 4. UÇTAN UCA AKIŞ — `pentest <hedef>`

```
1. KUR        pentest.sh <hedef>  → workspace + ACTIVE_TARGET + run objesi + scope + preflight
                                    + kb_load (aynı hedef geçmişi) + kb_similar (benzer hedefler)
2. CYPTURE      MCP araç adı keşfi → cyp_prefix.sh. Scope oluştur. TÜM trafik Cypture'dan (curl YASAK).
3. RECON      recon-agent'ı PARALEL kollara böl → task() spawn. URL'ler → surface_build.sh (INGEST).
4. ANLA       theory_build.sh → hedefin TEORİSİNİ kur; data-flow skill'iyle keskinleştir.
              reason_hypotheses.sh → teoriden SOMUT test üret. kb_similar/kb_patterns → geçmişten tohumla.
              prioritize.sh · class_select.sh (lens).
5. DÖNGÜ      a) decide_next.sh → en değerli işi söyler
              b) SPAWN: model = model_pick.sh; KİRALA: assign_agent.sh; işi cypture alt-ajanına task() ile ver
                 (Sisyphus/generic worker'a ASLA; model hatasında model_health auto + sıradaki modelle respawn)
              c) DALGA SONU TEK ÇAĞRI: wave_finalize.sh <surf> <cyp_json>
                 = collect_signals → oob_poll → anomaly_scan → gap_finder → audit_signals →
                   mark_from_engine(her host) → budget_guard → propagate_finding → chain_suggest → decide_next
              d) (a)'ya dön — KALAN bitene kadar ASLA durma, kullanıcı bekleme
6. RAPOR      STOP gelince reporter-agent → yalnız validated bulgular. STOP'ta kb_save → kb_mine (çark döner).
```

Pano her an: `status.sh` (host/sınıf/sinyal/bütçe/teori/inanç/model + sıradaki karar, tek ekran).

---

## 5. BİLİŞ KATMANI — gerçek hacker zihni (Phase 3)

Hacker-zihni bilgisi `skills/`'te actionable var; biliş motorları onu modelin *umduğu* prozadan, döngünün
*zorladığı* deterministik artefaktlara çevirir.

| Motor | Script | Ne yapar |
|---|---|---|
| **Hedef teorisi** | `theory_build.sh` · `theory_gate.sh` | Saldırmadan ÖNCE anla: ne, değerli varlık, aktör, güven sınırı, kritik akış, geliştirici profili, açık sorular. Sorular cevaplanmadan "tükendi" denmez. |
| **Niyet-hipotez** | `reason_hypotheses.sh` | Testi TEORİDEN üret ("userA, userB'nin parasını görebilir mi?"), param-brute'tan değil. |
| **İş-etkisi skoru** | `score_hypotheses.sh` | Değerin nerede olduğunu bil: /transfer IDOR ≫ /avatar IDOR. |
| **Anomali sezgisi** | `anomaly_scan.sh` | "Bu tuhaf": timing sapması, sızan iç alan, kardeş-endpoint auth tutarsızlığı → merak hipotezi. |
| **Boşluk reasoner** | `gap_finder.sh` | Buglar varsayımın çöktüğü yerde: method-authz boşluğu, v1/v2 drift, tutarsız doğrulama. |
| **İnanç + çürütme** | `belief.sh` | Bilim insanı: teori tut (assert), gözlemle güncelle (support/contradict), yüksek-güvenli kanıtsız inancı aktif ÇÜRÜT. Kanıtlanırsa → validate_finding. |
| **Zincir motoru** | `chain_suggest.sh` | Düşük-tek bulgu → kritik-bileşik: ssrf→metadata, open_redirect+oauth→token, idor+reset→ATO, lfi→RCE. |
| **Geri-besleme** | `propagate_finding.sh` | Bir yerde çalışan deseni HER YERE yay (aynı param/sınıf diğer host'lara öncelikli hipotez). |

---

## 6. ÖĞRENME ÇARKI — deneyim hafızası (Phase 4)

Daha çok test → daha büyük veri havuzu → daha iyi önseller → daha zeki avlanma → daha çok bulgu → daha zengin veri.

| Script | Ne yapar |
|---|---|
| `kb_load.sh` | Aynı hedefin önceki koşusunu yükle (bilinen tech/auth seed, suspicious→öncelik, dead_ends→skip). |
| `kb_similar.sh` | BENZER geçmiş hedefleri tech imzasıyla bul → orada ne bulunduysa öncelikli hipotez, ne temizse skip-notu. |
| `kb_mine.sh` | Tüm korpustan frekans-ağırlıklı AMPİRİK örüntü çıkar ("rails→idor N kez") → `_global-patterns.md` + `_mined.json`. |
| `kb_patterns.sh` | `_global-patterns.md` kurallarını (elle + ampirik) önsel hipoteze çevir. |
| `kb_save.sh` | Koşu sonu: surface'i `targets/_knowledge/<target>.json`'a damıt + kb_mine (çark). |

> **Dürüst sınır:** Bunlar ÖNSEL/ipucu, KANIT değil — her hedefte yine baseline + kanıt kapısı (FP üretmez).
> Öğrenme sinyali ancak gerçek **validated bulgu** biriktikçe oluşur; veri azken zararsız, biriktikçe keskinleşir.

---

## 7. SİNYAL MOTORU + HAKEMLER (mutlak doğruluk — Phase 1/2)

**Keşif (model-bağımsız):** `collect_signals.sh` her Cypture yanıtını BAYT BAYT tarar (sql_error, stack_trace,
reflection_xss, open_redirect, ssrf_oob, server_error, secret_leak) + FP ön-filtreleri → `signals.jsonl`.
`oob_canary.sh`/`oob_poll.sh` kör zafiyet (QuickSSRF) için canary üretir+yoklar. `audit_signals.sh` adayları
finding iskeletine çevirip kapıdan geçirir.

**Hakemler (kararı MODEL DEĞİL SCRIPT verir):**

| Script | Karar |
|---|---|
| `validate_finding.sh` | Bulgu kapısı: boundary + somut impact + deviation_req(her zaman) + baseline_req(kıyas tipleri) + referee. Severity KANITA bağlı (CRITICAL anahtar-kelimeyle değil, hakem verdict'iyle). |
| `diff_idor.sh` | IDOR/BOLA: 2 kimliğin yanıtını kıyaslar; "public veriye IDOR" hatasını öldürür. |
| `mark_from_engine.sh` | KANITLI derinlik: Cypture trafiğinden L0–L3 (authority'ye çapalı host eşleşme). |
| `coverage_status.sh` | Host kapsaması (lease-farkında) — her subdomain incelensin. |
| `class_coverage.sh` / `class_select.sh` | Sınıf LENS'i (akı hatırlatıcı, ZORUNLU kapı değil). |

---

## 8. DAYANIKLILIK (Phase 2)

- **Ajan watchdog** — `assign_agent.sh` host kiralar; `agent_health.sh` `last_heartbeat` `AGENT_TTL`(600sn) aşan
  ajanı stale yapıp kirasını serbest bırakır (host re-queue) → **ölü VE asılı ajan otomatik kurtarılır, döngü kilitlenmez.**
- **Model kademesi** — `model_registry.txt` (yetenek+maliyet), `model_health.sh` (auto: kota/rate/down sınıflar),
  `model_pick.sh` (o an çalışanlar içinden göreve en mantıklısını HESAPLAR). Free bitince sıradaki çalışan modele
  düşer; hepsi kalıcı bittiyse `STOP NO_WORKING_MODEL`, hepsi geçici soğuyorsa `CONTINUE-WAIT`.
- **Bütçe/rate** — `budget_guard.sh` (istek sayımı + 429 throttle). **Tek-çağrı dalga-sonu** (`wave_finalize.sh`)
  zayıf-modelin adım-atlama hata yüzeyini sıfırlar.

---

## 9. AJANLAR & MODEL

| Ajan | Mode | Rol |
|---|---|---|
| **cypture-orchestrator** | primary | BAŞ YÖNETİM — her task'ı O verir, böler, döngüyü sürer, toplar. Saldırmaz. Prompt ~170 satır (reçete+işaretçi). |
| recon-agent | subagent | Keşif + semantik (subdomain/JS/tech/WAF/port/cloud) |
| fuzzing-agent | subagent | Adaptif fuzz (tech'e göre wordlist) |
| web-test-agent | subagent | Web sink'leri (XSS/SQLi/SSRF/SSTI/IDOR/…) — Gözlem→Hipotez→Test |
| api-test-agent | subagent | API (BOLA/BFLA/mass-assignment/JWT/GraphQL) |
| reporter-agent | subagent | Yalnız STOP sonrası, validated bulgular — CVSS + profesyonel TR rapor |

- **Model:** Ajan frontmatter'larında `model:` YOK → **oturum modelini miras alırlar.** Oturumu çalışan
  bir modelle başlat (ör. `openai/gpt-4o`). Sabit "erişilemeyen model" derdi böyle biter.
- **Tek doğruluk kaynağı:** `.cypture/agents/*.md`. (`.claude/agents/` Claude-uyumluluk kopyalarıdır; cypture-agent
  konteynerinde KULLANILMAZ — `.dockerignore` ile dışlanır, yoksa `mode:` taşımadıkları için primary ajanları
  subagent'a düşürüp gölgelerler.)

---

## 10. SCRIPT ENVANTERİ (43)

**Çekirdek döngü:** `pentest.sh` · `decide_next.sh` · `score_hypotheses.sh` · `wave_finalize.sh` · `status.sh`
**Biliş (Phase 3):** `theory_build.sh` · `theory_gate.sh` · `reason_hypotheses.sh` · `anomaly_scan.sh` · `gap_finder.sh` · `belief.sh` · `chain_suggest.sh` · `propagate_finding.sh`
**Öğrenme (Phase 4):** `kb_load.sh` · `kb_similar.sh` · `kb_mine.sh` · `kb_patterns.sh` · `kb_save.sh`
**Sinyal/kanıt:** `collect_signals.sh` · `audit_signals.sh` · `validate_finding.sh` · `diff_idor.sh` · `oob_canary.sh` · `oob_poll.sh`
**Kapsama/derinlik:** `coverage_status.sh` · `class_coverage.sh` · `class_select.sh` · `prioritize.sh` · `mark_tested.sh` · `mark_class.sh` · `mark_from_engine.sh` · `next_hypothesis.sh` · `surface_build.sh`
**Dayanıklılık:** `assign_agent.sh` · `agent_health.sh` · `model_health.sh` · `model_pick.sh` · `budget_guard.sh`
**Scope/entegrasyon:** `scope_fetch.sh` (+`lib/registrable_domain.sh`, PSL) · `cyp_prefix.sh` · `preflight.sh` · `mark_identity.sh` · `acquire_identity.sh`

**Bilgi katmanı (`skills/`, 45 dosya):** çekirdek sözleşme (`core-contract`, `evidence-discipline`,
`baseline-and-signal`, `engine-mcp-contract`, `surface-schema`), muhakeme (`attacker-mindset-and-persistence`,
`data-flow-and-mental-model`, `access-control-reasoning`, `business-logic-reasoning`, `chain-attack-builder`,
`out-of-band-testing`, `target-knowledge-base`, `identity-acquisition`) + 23 vuln oyun-kitabı (`vuln-*.md`).

---

## 11. ÇALIŞTIRMA

```bash
bash scripts/preflight.sh                 # araç/Cypture/ağ kontrolü
# cypture-agent'da: oturumu ÇALIŞAN modelle başlat (ör. openai/gpt-4o) — erişilemeyen bir provider'ı kullanma
# cypture-orchestrator ajanını seç → "pentest privy.io"  (ya da: hackerone:privy)
bash scripts/status.sh                     # her an tek-ekran durum + sıradaki karar
# Acil durdurma: touch .cypture/plugin/ENFORCER_OFF
```

**Bağımlılıklar:** `jq`, `curl`, recon araçları (subfinder/httpx/gau/katana/ffuf/amass), Cypture + MCP server
(`localhost:8080`). Plugin (cypture-agent): `.cypture/plugin/loop-enforcer.js` (varsayılan AÇIK).

---

## 12. TASARIM İLKELERİ + DÜRÜST SINIR

1. **Karar modelden çıkar, koda girer** — bitti mi/gerçek mi/hangi açı/hangi model: hepsi script.
2. **Kanıt-takıntılı** — request_id zorunlu; halüsinasyon 3-soru kapısında ölür; yalnız KANIT rapora girer.
3. **Checklist yok** — "X sınıf kaldı" diye iş üretmez; subdomain'i mantık + gözlem + geçmişle DİKKATLİCE inceler.
4. **Sessiz fallback yok** — Cypture yoksa DUR, ACTIVE_TARGET yoksa enforcer atıl, working-model yoksa STOP.
5. **Token ekonomisi** — mekanik iş script'te; model jq dilimi + kısa özet okur (büyük ham çıktı basılmaz, TUI bozulmasın).
6. **Asla erken kapanış** — `decide_next.sh` CONTINUE derken "bitti/rapor/bekliyorum" geçersizdir.

> **Dürüst sınır:** Yaratıcı "aha" anı modelin bilişindedir; mimari modelde olmayan zekâyı ÜRETEMEZ. Ama elit
> avcı SÜRECİNİ zorlar, muhakemeyi biriktirir (teori+inanç+deneyim koşular arası keskinleşir) ve modeli her adımda
> tek en değerli soruya nişanlar.

```
Keşif savaşın yarısıdır. Teori + mantık + anomali + zincir + kanıt kapısı + biriken deneyim — savaşın tamamıdır.
```

> Geçmiş kararlar/bug'lar/felsefe: `memory/cypture-orchestrator-behavior.md`.
