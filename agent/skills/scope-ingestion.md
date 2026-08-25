---
name: scope-ingestion
description: >
  "İsim/handle ver, scope'u kendi kursun" otomasyonu. Bug bounty platform handle'ından (HackerOne/
  Bugcrowd/Intigriti/YesWeHack) in/out-of-scope varlıkları DETERMINISTIK çeker (script ile, token
  harcamadan), scope.md'yi doldurur ve Cypture scope'unu kurar. Recon doğrudan başlar. Orkestratör ADIM 0.5.
---

# 🛰️ SCOPE AUTO-INGESTION — handle ver, gerisi otomatik

> **Tek cümle:** Operatör `bounty h1:program-handle` der; sistem scope'u platformdan çeker,
> `scope.md`'yi doldurur, Cypture scope'unu kurar — sen tek satır yazmadan. Mekanik iş script'te,
> model sadece özeti okur (token-ucuz).

İlişkili: [[workspace-protocol]], [[engine-mcp-contract]], [[autonomy-loop]] (maliyet modeli), [[request-economy]].

---

## 1. İKİ KAYNAK

```
A. PUBLIC VERİ SETİ (varsayılan, token GEREKMEZ) — arkadiyt/bounty-targets-data
   Günlük güncel. Public program'ların in/out scope'u. Hızlı, sıfır-config.
   → scripts/scope_fetch.sh <platform> <handle> <output_dir>

B. PLATFORM API (private program için, token gerekir)
   HackerOne: API username+token (Basic auth) · Bugcrowd/Intigriti/YesWeHack: kendi token'ı.
   Token'ları cypture-agent env/config'e koy; A başarısızsa veya private ise B'ye düş.
   (Bu repoya token YAZMA — .gitignore + env.)
```

---

## 2. KULLANIM (orkestratör — workspace bootstrap'tan hemen sonra)

```
1. Komut formatı: "bounty <platform>:<handle>"  (örn. bounty h1:acme,  bounty bugcrowd:acme)
   platform kısayolları: h1→hackerone, bc→bugcrowd, intigriti, ywh→yeswehack.
2. Script'i çağır (mekanik, ucuz):
     scripts/scope_fetch.sh hackerone acme targets/acme__<tarih>/
3. Script ÇIKTISINI oku (KISA özet + in-scope hostname listesi) — JSON'u model parse ETMEZ.
4. scope.md otomatik yazıldı → GÖZDEN GEÇİR (yanlış/fazla varlık var mı?), gerekirse düzelt.
5. Cypture scope kur: in-scope hostname'lerden allowlist, out-of-scope'tan denylist:
     cyp_create_scope(name="<handle>", allowlist=[in-scope hostlar], denylist=[out hostlar])
6. In-scope hostname listesini recon'a besle (subdomain keşfi buradan başlar → surface.json).
```

> Script yoksa/başarısızsa (ağ, jq yok, program bulunamadı): DUR, operatöre bildir, scope.md'yi
> ELLE doldurmasını iste. Scope'u UYDURMA — kapsam hatası yasal risktir.

---

## 3. NORMALİZASYON (script yapar, model değil)

```
*.example.com / https://example.com/path  →  example.com   (şema/path/yıldız temizlenir)
Wildcard'lar subdomain keşfine, düz domain'ler doğrudan hedefe gider.
Mobil/binary/source-code varlıkları ayrı işaretlenir (web/API testinin dışında).
```

> ⚠️ NORMALİZE = "yıldızı sil", "kapsamı daralt" DEĞİL. `*.example.com → example.com` çıktısı
> "**example.com'un TÜM subdomain'lerini keşfet+test et**" demektir, "sadece example.com'a bak" değil.

---

## 3.5 SCOPE = TÜM EVREN (girdi sayısı ≠ hedef sayısı) — ⛔ KRİTİK

Platform scope'unda az satır olması (örn. 2 girdi) küçük yüzey demek DEĞİLDİR. Her in-scope girdi,
altındaki HER ŞEYİ kapsar. Literal string'leri "hedef listesi" sayıp orada DURMA — enumerate et:

```
WILDCARD  *.example.com  → subfinder + amass + crt.sh + DNS brute → çıkan HER canlı subdomain in-scope.
                           Hepsini surface.json'a al, recon fan-out ile test evrenine yay.
APEX/URL  example.com    → host + TÜM path/endpoint (katana/gau/wayback + JS endpoint çıkarımı).
CIDR/IP   1.2.3.0/24     → aralıktaki TÜM canlı IP/host.
```

- 2 wildcard girdi → potansiyel YÜZLERCE subdomain. "2 hedef test ettim" = HATA.
- Genişletme YALNIZCA in-scope girdilerin ALTI içindir. out-of-scope + 3rd-party'ye taşma YASAK
  (her keşfedilen host, istek atılmadan ÖNCE §4 scope kapısından geçer).
- Subdomain keşfi "boş/az" çıkarsa: amass passive+active, farklı kaynaklar, daha geniş wordlist DENE —
  erken pes etme. Subdomain bulamamak ≠ subdomain yok.

---

## 3.6 SCOPE MODELİ — 3 tür var, doğru olanı SEÇ (en sık yanılgı burada) ⛔

> GERÇEK: Çoğu program in-scope'u TAM yazmaz; sadece OUT-OF-SCOPE'u net belirtir ve "gerisi serbest"
> der. Bu durumda structured in-scope listesi (örn. 5 host) bir TAVAN DEĞİL, garanti-dahil bir ALT
> KÜMEDİR. "Out-of-scope'ta yok = test edilebilir" mantığı bu programlarda DOĞRUdur.

```
MODEL 1 — WILDCARD:  scope'ta *.example.com VAR → tüm subdomain'ler in-scope (§3.5).
MODEL 2 — AÇIK / DIŞLAMA-TABANLI:  policy "out-of-scope dışında her şey" / "all *.example.com" /
          "any asset owned by X" diyor → KÖK domain'i enumerate et (scope_fetch ÇIKTISINDAKİ KÖK
          DOMAIN), OUT-OF-SCOPE'u ÇIKAR, geri kalan TÜM canlı subdomain'leri test et.
          (Structured 5 host yalnız garanti-dahil; gerçek evren = tüm subdomain'ler − out-of-scope.)
MODEL 3 — KATI / LİSTE:  policy SADECE belirli host'ları yetkilendiriyor, "gerisi serbest" DEMİYOR
          → yalnız listelenen host'lar. Listede/wildcard'da olmayan subdomain = YETKİSİZ, DOKUNMA.
```
**MODELİ NASIL SEÇERSİN (sıra önemli):**
1. scope_fetch çıktısında wildcard varsa → MODEL 1.
2. Yoksa → H1/program POLICY METNİNİ oku (`cypture`/web ile program sayfası ya da operatöre sor):
   "out-of-scope dışında her şey", "all subdomains", "any Privy-owned asset" → MODEL 2 (AÇIK).
   Sadece spesifik host listesi + "yalnız bunlar" → MODEL 3 (KATI).
3. Operatör "full scan" / "out-of-scope olmayan her şeye bak" dediyse VE policy bunu yasaklamıyorsa
   → MODEL 2 uygula: KÖK domain'i enumerate et, out-of-scope'u çıkar, hepsini surface.json'a al.
- **OUT-OF-SCOPE her modelde KESİN denylist** — apex/host orada ise asla dokunma (ama apex out iken
  subdomain'ler in olabilir: privy.io OUT ama *.privy.io subdomain'leri MODEL 2'de IN).
- Şüphede DUR ve operatöre "bu program KATI mı AÇIK mı?" diye SOR — yanlış model = ya eksik tarama ya ban.

---

## 4. SCOPE DOĞRULAMA KAPISI (her istekten önce)

```
[ ] Hedef host scope.md IN-SCOPE'ta mı? Değilse → İSTEK ATMA.
[ ] OUT-OF-SCOPE listesinde mi? → kesinlikle dokunma.
[ ] Cypture scope (denylist) ikinci savunma — ikisi de sınırdır.
[ ] Program kuralları (rate, yasak test) scope.md'de mi, uyuluyor mu?
```

---

## ÖZET — 5 KURAL

1. "bounty <platform>:<handle>" → scripts/scope_fetch.sh ile scope'u DETERMINISTIK çek.
2. Public veri seti varsayılan (token yok); private için platform API (token env'de, repoda değil).
3. Script özetini oku, JSON'u model parse etme; scope.md otomatik dolar, gözden geçir.
4. In-scope'tan Cypture scope kur, hostname'leri recon'a besle.
5. Çekilemezse DUR ve elle iste; scope'u asla uydurma (yasal sınır).
