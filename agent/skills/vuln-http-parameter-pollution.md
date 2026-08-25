---
name: vuln-http-parameter-pollution
description: >
  Aynı parametre adı birden fazla kez gönderildiğinde (`?a=1&a=2`) farklı
  katmanlar (WAF, app, backend) farklı kopyayı seçiyorsa uygulanır. Precedence
  ayrışmasıyla WAF bypass, logic/auth bypass, price/parameter tampering dener.
  Ana karar: duplicate param hangi katmanda hangi değere çözülüyor ve bu
  ayrışma somut bir güvenlik kararını mı atlıyor?
---

# 🔀 HTTP PARAMETER POLLUTION — katmanlar duplicate param'ı farklı çözüyorsa açıktır

> **Tek cümle:** Aynı parametreyi çoğalt; kanıt, WAF/app/backend'in FARKLI kopyayı seçtiğini gösteren ölçülebilir karar ayrışması (bypass / tampering) — sadece "iki değer gönderdim" değil.

İlişkili: [[evidence-discipline]] [[baseline-and-signal]] [[engine-mcp-contract]] [[chain-attack-builder]] [[data-flow-and-mental-model]] [[request-economy]] [[vuln-sqli]] [[vuln-business-logic]] [[vuln-access-control]] [[attacker-mindset-and-persistence]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- İstek aynı parametreyi birden çok kez taşıyabiliyorsa ve arada birden fazla katman varsa: WAF/edge + app framework + backend/microservice; query + body karışımı; proxy'den geçen API.
- İpuçları: WAF arkasındaki uygulama, farklı dillerde mikroservisler (PHP gateway → Java backend), `amount`/`role`/`user_id`/`price` gibi güvenlik-kritik parametreler, izin/fiyat kararını parametreye bağlayan akışlar.
- SKIP: tek katman ve tek parametre kopyası anlamlıysa (duplicate'in hiçbir farkı yoksa) bu sınıf değildir; injection aranıyorsa ilgili skill (`'` → [[vuln-sqli]]).

## 2. İNSAN MUHAKEMESİ
- HTTP duplicate parametre davranışını standart tanımlamaz; her stack farklı seçer. Precedence matrisi (yaklaşık, doğrula):
  - **PHP/Apache:** SON kopya kazanır (`a=1&a=2` → `2`).
  - **ASP.NET / IIS:** kopyalar BİRLEŞTİRİLİR virgülle (`a=1&a=2` → `1,2`).
  - **JSP/Tomcat, Python (çoğu), Go `Query().Get`:** İLK kopya kazanır (`→ 1`).
  - **Node/Express:** duplicate'leri DİZİ yapar (`['1','2']`).
- Saldırı: WAF ilk kopyayı (zararsız) inceler, backend son kopyayı (zararlı) kullanır → WAF bypass. Ya da yetki kontrolü ilk `user_id`'yi, veri katmanı ikinciyi okur → access/price tampering.
- Kaçırılan yer: gateway ve servis farklı diller; "tek değer geldi" varsayan validasyon.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Tekil parametreyle normal istek; status + body + (varsa) yansıyan değeri not et. request_id sakla. Negatif kontrol: tek meşru değer.
- **Kademeli prob:**
  1. **Precedence tespiti:** `?a=BASE1&a=BASE2` (ayırt edilebilir iki değer) gönder → yanıt/davranış hangisini kullandı? İlk mi, son mu, birleşik mi, dizi mi? Bu, backend precedence'ını sabitler.
  2. **WAF bypass:** zararlı payload'ı (örn. `q=1' OR '1'='1`) ikinci kopyaya, zararsızı ilkine koy (`q=safe&q=<payload>`) → WAF geçti ve payload backend'de işlendi mi? Sıralamayı ters de dene.
  3. **Logic/price/auth:** `role=user&role=admin`, `amount=100&amount=1`, `user_id=<ben>&user_id=<kurban>` → güvenlik kararı hangi kopyaya bağlı, atlanabiliyor mu?
  4. **Katman ayrışması:** aynı param'ı hem query hem body'de gönder (`?id=A` + `id=B`), farklı casing/encoding kopyaları (`a` vs `%61`) — hangi katman hangisini görüyor.
- **Cypture notu:** `cyp_send_request` ile ham isteği elle kur (duplicate param'ları aracın normalize etmesine izin verme); `cyp_compare_requests` ile baseline ↔ pollution yanıtını diff'le.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** İki kopyadan biri davranışı deterministik belirliyor (precedence netleşti); WAF'ın bloklamadığı payload pollution ile backend'de işleniyor; `role`/`amount`/`user_id` pollution güvenlik kararını deterministik atlıyor.
- **Gürültü (aday DEĞİL):** duplicate gönderince hiçbir fark olmaması; her iki sırada aynı sonuç (precedence yok); WAF her iki kopyayı da görüp bloklaması; tek seferlik garip cevap; sadece "iki değer kabul edildi" ama karar değişmedi.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Precedence:** `a=BASE1&a=BASE2` ile yanıtın HANGİ kopyayı yansıttığını/kullandığını göster (BASE1 mi BASE2 mi birleşik mi). Ters sıra ile teyit. İki request_id.
- **WAF bypass:** tekil payload bloklanıyor (request_id A, blok), pollution'lı aynı payload geçip backend'de etki üretiyor (request_id B, injection/etki kanıtı). Negatif kontrol: zararsız pollution normal davranıyor.
- **Logic/auth/price tampering:** pollution'lı istek yetkisiz/indirimli sonucu verirken (request_id), tekil meşru istek vermiyor (baseline request_id). Etkiyi (fiyat değişti / admin erişimi) somut göster.
- Her iddia baseline + tetikleyici request_id ile.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Konum ekseni:** query string, POST body (`application/x-www-form-urlencoded`), multipart, JSON içinde duplicate key, query+body karışımı, cookie duplicate.
- **Sıra ekseni:** payload'ı ilk / son / ortada konumlandır; precedence matrisine göre kazanan slota koy.
- **Encoding ekseni:** kopyalardan birini URL-encode/çift-encode (`a` vs `%61`), boşluk/`[]` ekleme (`a[]=1&a[]=2`, PHP array), case farkı.
- **Katman ekseni:** WAF ilk-okur / backend son-okur ayrışmasını sömür; mikroservis sınırında (gateway dili ≠ servis dili) precedence farkını hedefle.
- **Zincir ekseni:** pollution ile WAF'ı geçip SQLi/XSS/SSRF payload'ını ilet → ilgili skill ([[vuln-sqli]] vb.). Sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** "İki değer gönderdim, kabul etti" demeyi açık sanmak. Bir GÜVENLİK KARARININ (WAF/auth/price) farklı kopya seçimiyle atlandığını göstermeden HPP impact'i yok.
- **Precedence'ı varsaymak:** matrisi ezbere kabul etme; `BASE1/BASE2` probuyla backend'in gerçekte hangisini seçtiğini ÖLÇ. Yanlış stack varsayımı tüm sonucu bozar.
- **Aracın normalize etmesini gerçek davranış sanmak:** test aracı/proxy duplicate'i birleştirebilir/sileceği için ham isteği elle kur; hedefin yorumuna bak.
- **WAF'ın hâlâ blokladığını bypass sanmak:** pollution'lı payload da bloklanıyorsa bypass yok.
- **Injection'ı HPP sanmak:** tek kopyada da çalışan `'`/payload HPP değil, doğrudan injection'dır → ilgili skill.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** precedence ölçüldü + farklı kopya seçimiyle somut güvenlik kararı atlandı (WAF bypass / auth / price) + negatif kontrol + tekrarlı.
- **Sinyal yok, kapat:** konum/sıra/encoding/katman eksenleri denendi; duplicate hiçbir karar ayrışması üretmiyor (her katman aynı kopyayı görüyor).
- **Şüpheli, ilerle:** precedence farkı var ama henüz güvenlik kararına bağlanmadı (sadece yansıma farkı) → tek hedefli prob daha (WAF/auth slotuna payload), sonra karar; bütçeyi boşa harcama.

## ÖZET — 5 KURAL
1. Önce `a=BASE1&a=BASE2` ile backend precedence'ını ÖLÇ — matrisi varsayma.
2. Ham isteği elle kur; aracın duplicate'i normalize etmesine izin verme.
3. "İki değer kabul edildi" KANIT DEĞİL — atlanan somut güvenlik kararı (WAF/auth/price) şart.
4. WAF bypass'ı: tekil payload blok + pollution'lı payload geçti + backend'de etki, üç istekle göster.
5. Her kanıt = baseline request_id + tetikleyici request_id; tek kopyada çalışan payload'ı HPP sanma → injection skill'i.
