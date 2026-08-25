---
name: vuln-websocket
description: >
  WebSocket güvenlik sınıfı: kalıcı WS kanalı üzerinden Cross-Site WebSocket
  Hijacking (CSWSH), mesaj kurcalama/enjeksiyon, mesaj-başına eksik yetkilendirme
  ve WS üzerinden hassas veri sızması. Ana karar: WS handshake'i Origin doğrulamadan
  cookie ile mi kuruluyor (CSWSH), ve mesaj seviyesinde authz var mı?
---

# 🔌 WEBSOCKET — Origin'siz cookie auth + mesaj-başına yetkisiz işlem açıktır

> **Tek cümle:** WS handshake cookie ile kimliklenip Origin doğrulanmıyorsa (CSWSH) ya da her mesaj ayrı yetkilendirilmiyorsa, kanıt = kaynaklar arası kurulan/kurcalanan kanaldan ÖLÇÜLEBİLİR yetkisiz yanıt akışıdır.

İlişkili: [[access-control-reasoning]] (mesaj-başına authz) [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] (`cyp_list_ws_streams`/`cyp_list_ws_messages`) [[request-economy]] [[vuln-csrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Uygulama bir WS kanalı açıyorsa: canlı bildirim, sohbet, fiyat/feed akışı, dashboard, collaborative editing, terminal/SSH-over-WS, oyun durumu.
- İpuçları: `Upgrade: websocket` handshake, `wss://<hedef>/...`, `Sec-WebSocket-Key`, JS'te `new WebSocket(...)`. `cyp_list_ws_streams` ile aktif kanalları, `cyp_list_ws_messages` ile mesaj trafiğini çıkar.
- SKIP: WS yoksa; kanal tamamen public/anonim ve hassas veri/işlem taşımıyorsa (CSWSH'nin değeri yok); auth WS handshake'te değil her mesajda token ile yapılıp doğrulanıyorsa CSWSH zemini zayıftır.

## 2. İNSAN MUHAKEMESİ
- **CSWSH:** WS handshake sıradan bir cross-origin GET'tir; tarayıcı cookie'leri OTOMATİK ekler ve Same-Origin Policy WS'i aynı şekilde KISITLAMAZ. Sunucu `Origin` header'ını doğrulamıyorsa, saldırgan sayfası kurbanın oturumuyla kanalı açıp veri okur/komut yollar — CSRF'in WS hali ama çift yönlü.
- **Mesaj-başına authz:** Geliştirici handshake'te bir kez yetki kontrol edip sonraki mesajlarda kontrol etmeyi unutmuş olabilir; tek kanaldan başka kullanıcının kaynağı istenebilir → [[access-control-reasoning]].
- Asıl mesele: handshake Origin'i mı doğruluyor, yoksa sadece cookie'ye mi güveniyor; ve her mesaj ayrı authz'a tabi mi.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Meşru oturumla kanalı normal kullan; `cyp_list_ws_messages` ile handshake header'larını (Origin gönderiliyor mu, doğrulanıyor mu) ve normal mesaj akışını/yanıt şeklini kaydet. Stream/mesaj id'lerini sakla.
- **Tek prob — CSWSH:** Handshake'i FARKLI/eksik `Origin` ile, ama kurbanın cookie'siyle yeniden kur (`cyp_send_request` Upgrade isteği):
  ```
  GET /ws  Upgrade: websocket  Origin: https://attacker.tld  Cookie: <kurban-oturumu>
  → 101 Switching Protocols döndü mü (Origin reddedilmedi mi)?
  ```
- **Tek prob — mesaj tampering/authz:** Kanal açıkken tek bir mesajı kurcala (başka kullanıcının kaynak id'si / yetkisiz komut) ve yanıtı izle:
  ```
  {"action":"get_messages","user_id":<başka-kullanıcı>}  → başkasının verisi döndü mü?
  ```

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Cross-origin handshake `101` ile KABUL edildi ve veri akmaya başladı (CSWSH); VEYA kurcalanan mesaj başka kullanıcının kaynağını/komutunu işledi (eksik mesaj-authz); VEYA kanaldan oturuma ait hassas veri (token, PII, özel mesaj) süzülüyor.
- **Gürültü (aday DEĞİL):** Handshake cross-origin'de reddediliyor (`403`/kapanış kodu 1008/4xx); kurcalanan mesaj "unauthorized"/hata dönüyor; akan veri public ve hassas değil; tek seferlik bağlantı kopması.

## 5. DOĞRULAMA KAPISI (kanıt)
- **CSWSH:** (1) Yanlış `Origin` ile `101` + veri akışı, (2) Negatif kontrol: cookie OLMADAN aynı handshake'in yetkili veri DÖNMEMESİ → demek ki tek dayanak ambient cookie. İki handshake request_id'si + akan mesaj id'leri.
- **Mesaj-authz:** Kullanıcı A'nın kanalından B'nin kaynağı geldi → A ve B oturumlarıyla çapraz doğrula (B'nin verisi A'ya sızdı). Stream/mesaj id'leriyle.
- **Hassas veri:** `cyp_list_ws_messages` çıktısından sızan alanı maskeli göster + bunun yetkisiz tarafa aktığını handshake bağlamıyla bağla.
- Her iddia: handshake request_id + `cyp_list_ws_streams`/`cyp_list_ws_messages` id'leri + negatif kontrol.

## 6. VARYASYON / BYPASS (handshake reddediliyorsa)
- **Origin ekseni:** Tamamen yabancı origin, `null` origin, subdomain/suffix-match zayıflığı (`hedef.com.attacker.tld`, `attackerhedef.com`) — gevşek regex'i sömür.
- **Auth ekseni:** Token cookie'de mi yoksa ilk mesajda mı; ilk mesajdaysa token'sız/başka-token ile authz atlanabilir mi.
- **Mesaj-tampering ekseni:** id/role/action alanlarını oynat, sıralı mesajlarda durum-makinesini boz (auth mesajını atlayıp doğrudan veri iste).
- **Protokol ekseni:** Subprotocol/compression header oyunları; mesaj formatı JSON↔binary.
- 3-5 origin/auth ekseninde sinyal yoksa "CSWSH yok / mesaj-authz sağlam" diye dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **`101` dönüşünü tek başına CSWSH sanmak:** Handshake kabul edilse bile YETKİLİ veri akmıyorsa (kanal cookie'siz de aynı public veriyi veriyorsa) CSWSH değil — ambient cookie'ye bağımlılığı negatif kontrolle kanıtla.
- **Public broadcast'i "hassas sızıntı" sanmak:** Herkese açık feed sızıntı değildir.
- **Kendi oturumunun verisini "başkasının" sanmak:** Mesaj-authz'da iki ayrı oturumla çapraz doğrula.
- **Bağlantı kopmasını blok sanmak:** Tek kopuş kanıt değil; tekrarla.
- **Origin yansımasını doğrulama sanmak:** Sunucu Origin'i geri yansıtıyor olabilir ama reddetmiyordur — kabul/ret davranışına bak, yansımaya değil.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Cross-origin handshake `101` + yetkili veri akışı + cookie'siz negatif kontrol başarısız (CSWSH); VEYA çapraz-oturum doğrulamayla mesaj-authz aşıldı; VEYA maskeli hassas veri yetkisiz akıyor.
- **Sinyal yok, kapat:** Cross-origin reddediliyor, mesajlar ayrı authz'a tabi, akan veri public → güvenli.
- **Şüpheli, ilerle:** Handshake kabul ediliyor ama veri public görünüyor → daha hassas action/mesaj-tampering dene, negatif kontrolü tamamla, sonra karar.

## ÖZET — 5 KURAL
1. `cyp_list_ws_streams`/`cyp_list_ws_messages` ile kanalları çıkar; baseline handshake + akışı kaydet.
2. CSWSH: yanlış `Origin` + kurban cookie ile `101` mı? Kanıt için cookie'siz negatif kontrol ŞART.
3. Mesaj-başına authz'ı çapraz-oturumla sına; bir kanaldan başkasının kaynağı geliyorsa bulgu.
4. `101` tek başına kanıt değil — yetkili/hassas veri akışını ve ambient-cookie bağımlılığını göster.
5. Public broadcast'i sızıntı, Origin yansımasını doğrulama sanma; her iddia stream/mesaj id'li.
