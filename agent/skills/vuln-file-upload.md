---
name: vuln-file-upload
description: >
  Dosya Yükleme Bypass sınıfı: bir yükleme akışı dosyayı kaydediyor/işliyorsa
  uygulanır. Yasaklı tip/içeriğin filtreyi atlayıp kabul edilip edilmediğini ve
  yüklenenin erişilebilir/çalışır olup olmadığını bulur. Ana karar: dosya SADECE
  kabul mü edildi, yoksa yolu/çalışması da KANITLANDI mı?
---

# 📤 DOSYA YÜKLEME BYPASS — yasaklı dosya kabul EDİLİYOR ve erişilebilir/çalışıyorsa açıktır

> **Tek cümle:** Filtreyi (uzantı/Content-Type/magic byte) atlatıp yasaklı bir dosya kabul ettir; kanıt "kabul edildi" değil, yüklenenin yolundan ERİŞİLEBİLİR ve (RCE iddiası varsa) ÇALIŞTIĞInı gösteren çıktıdır.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[vuln-xss]] [[vuln-ssrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- Bir multipart/form-data veya base64 gövdesi dosya kaydeden/işleyen bir sink'e gidiyorsa: avatar/profil resmi, belge/CV upload, import (CSV/XML), görsel işleme (resize/thumbnail), PDF/ofis dönüştürme.
- İpuçları: `filename=`, `Content-Type: image/...`, dönen bir URL/path/id, "yükleme başarılı" + erişilebilir bir kaynak.
- SKIP: hiçbir dosya kaydı/işlemesi yoksa. Yalnız resim metadata'sından SSRF tetikleniyorsa → [[vuln-ssrf]]; SVG render'dan script çalışıyorsa bu skill'de kal ama [[vuln-xss]]'i de düşün.

## 2. İNSAN MUHAKEMESİ
- Geliştirici tipi tek bir katmanda doğruluyor olabilir: ya sadece uzantıya, ya sadece Content-Type'a, ya sadece magic byte'a bakar. Tek katman → bypass.
- Kaçırılan yer: blacklist (allow-list değil); uzantıyı son nokta yerine ilk noktadan okumak; null byte / case duyarsızlığı; içeriğe bakmadan kaydedip web-erişilebilir dizine koymak; işleyici (ImageMagick/ffmpeg) güvenmediği formatı parse etmek.

## 3. TEŞHİS PROB'U (önce baseline, sonra TEK prob)
- **Baseline:** Geçerli bir resim yükle (gerçek PNG, doğru Content-Type). Dönen path/URL, status, "başarılı" mesajını ve erişim davranışını not et. request_id sakla.
- **Önce yüzeyi haritalandır:** filtre nerede uygulanıyor (uzantı mı, Content-Type mı, magic byte mı, gerçek re-encode mi)? Tek bir kontrollü değişiklikle hangi katmanın reddettiğini izole et — körlemesine 20 payload atma, [[request-economy]].
- **Tek prob (kademeli, her seferinde TEK eksen):**
  1. **Uzantı:** Aynı isteği `shell.php` (veya `.phtml`) ile gönder. Reddedilirse `shell.php.jpg`, `shell.jpg.php`, `shell.pHp`, `shell.php%00.jpg` varyasyonlarından TEK birini dene.
  2. **Content-Type:** PHP gövdesini `Content-Type: image/png` ile yolla; reddedilirse Content-Type'ı koru, sadece uzantıyı oynat.
  3. **Magic byte/polyglot:** Dosya başına `GIF89a;` + `<?php ... ?>` koy (kanonik polyglot), uzantı `.php` — magic byte kontrolünü geçer, çalıştırmayı dener.
- Her probdan sonra **dönen path'e GET at**: kaydedildi mi, içerik ham mı yoksa işlenmiş/çalışmış mı? Bu adım atlanırsa kanıt yoktur.
- **Cypture notu:** Multipart gövdeyi `send_request` ile tam kontrol et; `filename`, `Content-Type` ve ilk byte'ları elle düzenle. Upload yanıtındaki path için ayrı bir `send_request` ile GET at; her iki request_id'yi de sakla. [[engine-mcp-contract]] sınırları içinde kal, kör fuzz yapma.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Yasaklı tipte dosya 200/başarılı + erişilebilir bir yola düştü; VEYA SVG yüklenip render edilen sayfada `<script>` çalıştı; VEYA ImageMagick/ffmpeg girdisi beklenmedik davranış (OOB/dosya okuma) yaptı.
- **Gürültü (aday DEĞİL):** "Yükleme başarılı" mesajı ama dosyaya erişilemiyor / path dönmüyor; sunucu resmi yeniden encode edip payload'ı düşürmüş; 200 ama içerik sanitize edilmiş; WAF/jenerik hata.

## 5. DOĞRULAMA KAPISI (kanıt)
- **RCE iddiası:** yüklenen `.php`'nin **URL'sine GET** at → içindeki kanıt (örn. `<?php echo 7*7;?>` cevapta `49`, veya `<?php echo md5(unique);?>` benzersiz hash) DÖNDÜ. İki request_id: upload + çalıştırma. "Çalıştı" = baseline'da olmayan, sunucu-tarafı üretilmiş çıktı.
- **SVG→XSS:** dosyayı render eden bağlamda script tetiklenir (DOM/alert yerine OOB tercih); upload + render request_id.
- **İşleyici (ImageMagick/ffmpeg):** OOB callback'teki benzersiz token ↔ yüklenen dosyadaki token eşleşir.
- **Negatif kontrol:** aynı içeriği zararsız uzantıyla yolla → çalışmamalı; fark gerçek bypass'ı çıpalar. N tekrar.

## 6. VARYASYON / BYPASS (bloklanınca)
- **Uzantı ekseni:** double ext (`.php.jpg`/`.jpg.php`), alternatif (`.phtml`,`.phar`,`.phps`,`.pht`), case (`.PhP`), null byte (`x.php%00.jpg`), trailing (`x.php.`/boşluk/`::$DATA`). Sunucu yığınına göre seç: Apache+PHP → `.phtml`; IIS+ASP → `.asp;.jpg`; JSP → `.jsp`.
- **Content-Type ekseni:** beyan edilen tipi `image/*` yap, gövde gerçek payload; multipart boundary/charset hilesiyle parser farkı yarat.
- **Magic byte/polyglot:** `GIF89a;`, PNG header + payload, geçerli resim + EXIF/comment içine kod (re-encode'a daha dayanıklı).
- **Sink override:** `.htaccess` (Apache'de `.evil` → PHP handler) veya `web.config` overwrite ile çalıştırma kuralı ekle — yalnız yazılabiliyorsa.
- **İşleyici ekseni:** ImageMagick `MSL`/`ephemeral`/SVG SSRF, ffmpeg `concat`/HLS ile dosya okuma — işleme adımı varsa OOB ile yokla.
- **Path/erişim ekseni:** path traversal `filename=../../...` ile web-kök dışına/altına yazma; tahmin edilebilir yükleme dizini (timestamp/sıralı id). Her eksen hipotez; sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **"Kabul edildi" = RCE sanmak:** En büyük tuzak. Dosyanın kabulü, çalıştığını GÖSTERMEZ. Yol + çalışma kanıtı (cevapta sunucu-üretilmiş çıktı) olmadan RCE deme.
- **Erişilemeyen dosyaya RCE demek:** path dönmüyor / GET 403/404 ise çalıştırma kanıtı yok → en fazla "depolanmış, çalışma teyit edilemedi".
- **Re-encode'u görmezden gelmek:** sunucu resmi yeniden işlemişse polyglot payload düşmüştür; indirilen dosyada payload'ın hâlâ var olduğunu doğrula.
- **SVG'yi indirip XSS sanmak:** SVG ancak render edildiği bağlamda script çalıştırırsa XSS'tir; ham indirme tarayıcıda inline render edilmiyorsa FP.
- **Yansıyan filename'i çalıştı sanmak:** dosya adının cevapta görünmesi (reflection) çalışma değildir.
- **`.htaccess` yazıldı sanıp etki atlamak:** `.htaccess`/`web.config` kabul edilse bile sunucu onu UYGULAMIYOR olabilir (AllowOverride kapalı); kuralın gerçekten devreye girdiğini bir test isteğiyle doğrula.
- **Statik dosya sunucusunu çalıştırma sanmak:** path 200 dönüyor ama içerik ham metin olarak iniyorsa (handler yok) bu RCE değil; cevabın işlenmiş/üretilmiş çıktı olduğunu gör.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** yasaklı dosya kabul + erişilebilir yol + (RCE için) çalıştırma çıktısı / (XSS için) render'da tetikleme / (işleyici için) OOB — EN AZ BİRİ + negatif kontrol + N tekrar.
- **Sinyal yok, kapat:** uzantı/Content-Type/magic eksenleri denendi; ya reddedildi ya re-encode düşürdü ya erişilemiyor.
- **Şüpheli, ilerle:** dosya kabul edildi ama yol/erişim belirsiz → path keşfi (tahmin/traversal/listing) için bir hedefli prob daha, sonra karar.

## ÖZET — 5 KURAL
1. "Kabul edildi" ASLA RCE kanıtı değil; yol + çalışma (sunucu-üretilmiş çıktı) şart.
2. Her zaman dönen path'e GET at; erişilemeyen dosya = çalışma kanıtı yok.
3. Bypass'ı tek katmandan ara: uzantı, Content-Type, magic byte ayrı ayrı eksen.
4. Re-encode payload'ı düşürür; indirilen dosyada payload'ın sağ kaldığını doğrula.
5. Her kanıt = upload request_id + çalıştırma/render/OOB request_id + zararsız negatif kontrol.
