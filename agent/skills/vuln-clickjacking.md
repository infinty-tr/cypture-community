---
name: vuln-clickjacking
description: >
  Hassas, state-changing bir sayfa harici bir origin'de <iframe>'e gömülebiliyor
  ve UI-redress ile kurban tıklatılabiliyorsa uygulanır. missing XFO/CSP
  frame-ancestors, tek-tık state değişimi, cursorjacking/drag, sandbox bypass.
  Ana karar: çerçeve koruması yok + frame'lenince GERÇEK bir duyarlı etki var mı.
---

# 🖼️ CLICKJACKING — koruma yoksa duyarlı eylemi görünmez frame'de tıklatma

> **Tek cümle:** Sayfa başka origin'de frame'lenebiliyorsa ve o sayfada tek tıkla tetiklenen duyarlı bir eylem varsa, saldırgan kurbanı opak overlay altında o eyleme tıklatabilir — salt framability bulgu değildir, GERÇEK eylem şart.

İlişkili: [[data-flow-and-mental-model]] [[baseline-and-signal]] [[evidence-discipline]] [[engine-mcp-contract]] [[attacker-mindset-and-persistence]] [[request-economy]] [[chain-attack-builder]] [[vuln-csrf]]

## 1. NE ZAMAN UYGULANIR (sink/bağlam)
- SADECE şu varsa test et: **state-changing** veya hesaba etki eden bir sayfa (delete-account, change-email, transfer, OAuth/permission grant, makeAdmin, "Confirm/Approve/Subscribe" butonu) + sayfa cookie/session ile authenticated render oluyor.
- Tek tıkla (veya basit drag) tamamlanan bir aksiyon olmalı; multi-step + CSRF-token + re-auth gerektiren akışlar zayıf adaydır (ama drag/multi-click ile kısmen aşılabilir, §6).
- SKIP: statik içerik; login sayfası (henüz kimlik yok); duyarsız bilgi sayfası; API-only endpoint (UI yok, clickjacking tarayıcı UI gerektirir).

## 2. İNSAN MUHAKEMESİ
- Kullanıcının gördüğü buton = saldırganın gizlediği buton. Geliştirici "kimse bunu tıklatamaz" varsaydı ama frame koruması (`X-Frame-Options` / CSP `frame-ancestors`) koymadı.
- Soru: Bu sayfayı `<hedef-evil>` içinde iframe yaparsam tarayıcı render eder mi, yoksa boş/blank kalır mı? Render ederse → opaklığı düşür + üstüne sahte UI/yem koy + butonu cursor'un düşeceği yere hizala.
- CSRF ile farkı: clickjacking, CSRF-token'ı OLAN ama frame koruması olmayan eylemleri de vurabilir, çünkü kurbanın kendi tarayıcısı meşru token'lı isteği gönderir → [[vuln-csrf]] tamamlayıcısıdır.

## 3. TEŞHİS PROB'U (önce baseline, sonra kademeli)
- **Baseline:** Hedef duyarlı sayfayı normal GET ile çek (`cyp_send_request`). Yanıt header'larını ham oku, request_id sakla.
- **Kademeli prob:**
  1. **Koruma var mı:** Yanıtta `X-Frame-Options` (DENY/SAMEORIGIN) VE/VEYA CSP `frame-ancestors` direktifi var mı? İkisi de yok/zayıfsa → çerçevelenebilir aday. (Not: XFO `ALLOW-FROM` modern tarayıcıda yok sayılır; `frame-ancestors` asıl belirleyici.)
  2. **Gerçekten render oluyor mu:** Minimal local HTML'de `<iframe src="https://<hedef>/...">` ile sayfanın blank değil GERÇEK render olduğunu doğrula (bazı sayfalar JS framebuster ya da cookie `SameSite` yüzünden authenticated render etmez).
  3. **Eylem tek-tık mı:** Hedef butonun tek tıkla state değiştirdiğini önce normal akışta teyit et.

## 4. SİNYAL vs GÜRÜLTÜ
- **Aday (sinyal):** Koruma header'ı YOK/zayıf + sayfa authenticated render + üzerinde tek-tık duyarlı eylem + iframe'de görünür render (blank değil).
- **Gürültü:** Sadece `X-Frame-Options` eksikliği ama sayfa duyarsız/statik; `frame-ancestors 'none'` zaten varken XFO yokluğu (CSP yeterli); `SAMEORIGIN`/`frame-ancestors self` varken cross-origin frame'in zaten bloklanması; JS framebuster sayfayı top'a fırlatıyor; `SameSite=Lax/Strict` cookie yüzünden frame'de oturum yok (eylem anonim, etkisiz).

## 5. DOĞRULAMA KAPISI (kanıt)
- **PoC HTML:** hedefi `opacity:0` (veya düşük) iframe'e koy, butonu cursor'un düşeceği koordinata hizala, üstüne yem ("Click to win"/CAPTCHA) yerleştir.
- **Kanıt zinciri:** (1) koruma header'ı yok request_id (ham yanıt), (2) iframe'in render olduğu screenshot/gözlem, (3) PoC'de tıklamanın GERÇEK state değişikliğini tetiklediğinin sonraki istekle teyidi (örn. email gerçekten değişti), (4) negatif kontrol: `frame-ancestors` eklenmiş benzer bir sayfa frame'lenmiyor.
- **Etki cümlesi net olmalı:** "Tek tık → hesap silindi / email değişti / yetki verildi." Sadece "frame'lenebiliyor" yetmez.

## 6. VARYASYON / BYPASS (bloklanınca)
- **XFO `ALLOW-FROM` legacy:** modern tarayıcı yoksayar → CSP `frame-ancestors` yoksa hâlâ açık olabilir.
- **CSP eksik ama XFO `SAMEORIGIN`:** cross-origin bloklu, bypass yok → kapat (yanlış pozitif kurma).
- **Drag-and-drop / cursorjacking:** tek tık yetmiyorsa kullanıcıyı sürüklemeye (data/text drag) yönlendirip değer taşı; cursor'u sahte konumda göster.
- **Double-click / focus-then-click:** confirm dialog'unu frame zamanlamasıyla (hızlı çift tık) atlatma hipotezi; yem-then-gerçek-buton.
- **Multi-step redress:** CSRF-token'lı çok adımlı akışı ardışık hizalı tıklamalarla (her adım ayrı overlay) sürükleme.
- **Sandbox/nested frame:** bazı korumalar sadece top-level kontrol eder; iç (nested) frame veya `sandbox` iframe denemesi; `SameSite=None` cookie varsa frame'de oturum kalır.
- Sinyal yoksa dürüstçe kapat.

## 7. FALSE-POSITIVE TUZAKLARI (zayıf modelin halüsinasyonu)
- **"XFO yok → kritik clickjacking" demek:** GERÇEK duyarlı eylem + tıklama tetiği olmadan rapor = FP. Framability ≠ zafiyet.
- Statik/marketing/dokümantasyon sayfasını frame'leyip "vuln" sanmak.
- `SAMEORIGIN` veya `frame-ancestors` mevcutken yine de raporlamak.
- PoC'nin tıklamayı GERÇEKTEN tetiklediğini doğrulamadan teorik anlatmak.
- CSRF-token + re-auth gerektiren tek-adımı "tek tık" sanmak; ama tersi tuzak: token VARLIĞINI "korumalı" sanıp clickjacking'i atlamak — token frame'de kurbanın kendi oturumuyla gönderilir, koruma değildir.
- `SameSite=Lax/Strict` yüzünden frame'de oturum olmadığını fark etmeden "authenticated tıklama" sanmak.

## 8. DURMA KRİTERİ
- **Kanıtlandı, kapat:** Koruma yok/zayıf + iframe render + PoC'de tıklama gerçek duyarlı state değişikliği yaptı + negatif kontrol temiz.
- **Sinyal yok, kapat:** XFO `DENY`/`SAMEORIGIN` veya CSP `frame-ancestors` mevcut; sayfa duyarsız/statik; JS framebuster çalışıyor; frame'de oturum yok.
- **Şüpheli, ilerle:** Koruma yok ama eylem confirm/token/çok-adım istiyor → drag/double-click/multi-step redress eksenlerini (§6) dene.

## ÖZET — 5 KURAL
1. Önce ham header oku: XFO + CSP `frame-ancestors` ikisi de yok/zayıfsa devam et.
2. Duyarlı + authenticated + tek-tık (veya drag) eylem yoksa SKIP.
3. iframe'in gerçekten render olduğunu (blank/framebuster değil, oturumlu) gör.
4. Etkiyi PoC ile kanıtla — header eksikliği tek başına bulgu değildir.
5. Statik sayfa / mevcut koruma / oturumsuz frame = otomatik kapat, FP yazma.

## DOĞRULAMA — GÖRSEL KANIT
Çerçeveleme (frame) PoC sayfasını `cyp_browser_navigate` ile yükle, `cyp_browser_screenshot` al: hedef sayfanın saldırgan iframe'inde GÖRÜNÜR render olduğu görsel = kanıt. `path`'i `extracted_evidence`'a yaz. X-Frame-Options/CSP eksikliği TEK BAŞINA bulgu değil — görsel kanıtla executed_effect'e yükselt, yoksa OLASI/TEORİK bırak.
