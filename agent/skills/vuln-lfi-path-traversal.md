---
name: vuln-lfi-path-traversal
description: >
  Bir parametre dosya sistemi yolu olarak kullanıldığında (include/read/download/template) uygulanır.
  ../ dizilimi veya wrapper ile uygulama dizini dışına çıkıp keyfi dosya okutur.
  Ana karar: yol kontrol ediliyor mu — gerçek dosya içeriği mi döndü yoksa jenerik 404/hata mı.
---

# 📂 LFI / Path Traversal — path parametresiyle uygulama dizini dışına çık, dosya okut

> **Tek cümle:** Bir parametre dosyaya çözülüyorsa, `../` ile yukarı tırman ve sunucunun OKUYABİLDİĞİ bilinen bir dosyanın içeriğini geri al.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE bir girdi dosya sistemine ulaşıyorsa test et:
  - `?file=`, `?page=`, `?template=`, `?lang=`, `?download=`, `?path=`, `?doc=` gibi parametreler.
  - Dosya adı/uzantı yanıtta görünüyor, `Content-Disposition: attachment` var, ya da hata bir dosya yolu sızdırıyor.
- YOKSA: "SKIP: dosya-sistemi sink'i yok; parametre DB/route/identifier ise bu sınıf uygulanmaz."

## 2. İNSAN MUHAKEMESİ
- Uygulama `base_dir + kullanıcı_girdisi` ile bir path kuruyor. Sanitizasyon eksikse `../` segmentleri kökü değiştirir.
- Geliştirici uzantı ekliyor (`.php`, `.html`) → wrapper/null-byte gerekebilir; ya da blacklist `../` filtreliyor → encoding gerekir.
- Asıl mesele: girdi gerçekten `open()`/`include()` çağrısına mı gidiyor, yoksa bir whitelist'ten ID seçimi mi (o zaman LFI yok).

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Parametrenin meşru değeriyle iste; status, boyut, gövde imzasını not al. request_id sakla.
- **Tek prob:** Bilinen, var olması KESİN bir dosyayı hedefle — kör liste değil, tek kanonik dosya:
  ```
  GET /view?file=../../../../etc/passwd
  ```
- **Gözlem:** Yanıtta `root:x:0:0:` satırları VAR mı? Windows hedefse `../../../../windows/win.ini` → `[fonts]`.
- **Tek wrapper probu (PHP):** Kaynak kodu çekme: `php://filter/convert.base64-encode/resource=index.php` → base64 blok döndü mü.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** `/etc/passwd` formatlı içerik; `win.ini` `[fonts]`; base64 çözülünce PHP kaynağı; ya da hata mesajının sızdırdığı tam absolute path (`/var/www/html/...`).
- **Gürültü (sinyal DEĞİL):** Jenerik 404, "file not found", boş 200, WAF block sayfası. Bunlar erişim YOK demektir.

## 5. DOĞRULAMA KAPISI (kanıt)
- Baseline (meşru dosya, 200, normal içerik) vs traversal (sistem dosyası içeriği) farkı net olmalı.
- ≥2 farklı sistem dosyası oku (`/etc/passwd` vs `/etc/hostname`/`/proc/self/cmdline`) — içerikler FARKLI dönmeli; sabit/echo değil.
- Derinlik kontrolü: `../` sayısını azalt → içerik kaybolmalı (deterministik traversal kanıtı). Negatif kontrol: traversal'sız path sistem dosyası VERMEMELİ. request_id'leri yaz.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Encoding ekseni:** `%2e%2e%2f`, çift-encode `%252e%252e%252f`, `..%c0%af` (overlong UTF-8).
- **Filtre ekseni:** `....//` (özyinelemeli silme bypass), `..../`, mutlak path `/etc/passwd`.
- **Uzantı ekseni:** Sona uzantı ekleniyorsa `php://filter` wrapper; eski PHP'de null byte `%00` (legacy, çoğu yamalı).
- **Başlangıç ekseni:** App `./uploads/` prepend ediyorsa traversal o prefix'ten başlamalı; derinliği artır.
- **Proc ekseni:** `/proc/self/environ`, `/proc/self/cmdline` ile config/secret sızdırma. Sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **EN SIK:** 404'ü veya jenerik hata sayfasını "bulgu" sanmak. Erişilemeyen ≠ zafiyet.
- Kendi gönderdiğin path string'inin yansımasını "dosya okundu" sanmak.
- `win.ini`/`passwd` gibi kelimeleri içeren WAF/error sayfasını gerçek dosya sanmak — içerik FORMATINI doğrula.
- Sabit boyutlu aynı yanıtın her path'te dönmesi → traversal işlemiyor, statik response.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** ≥2 farklı sistem dosyası doğru formatta döndü + derinlik/negatif kontrol tutarlı.
- **Sinyal yok, kapat:** Tüm encoding/wrapper varyasyonları 404/jenerik hata; içerik hiç değişmiyor.
- **Şüpheli, ilerle:** Hata absolute path sızdırıyor ama içerik gelmiyor (path biliniyor, okuma engelli) → wrapper/proc eksenine devam, info-leak olarak not düş.

## ÖZET — 5 KURAL
1. Parametre dosya sistemine gitmiyorsa SKIP — DB/route ID'sini LFI sanma.
2. Kör liste yok: tek kanonik dosyayla (`/etc/passwd` / `win.ini`) teşhis et.
3. 404/jenerik hata KANIT DEĞİL — sadece doğru formatlı dosya içeriği bulgudur.
4. İki farklı dosya + derinlik azaltma + negatif kontrol ile doğrula.
5. Bloklanınca encoding, `....//`, wrapper, prefix-derinlik eksenlerini dene; boşsa kapat.
