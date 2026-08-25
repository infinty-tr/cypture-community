# SKILL: TLS / Kripto Denetimi (vuln-tls-crypto)
HTTPS hedeflerde sertifika/protokol/cipher ve uygulama-katmanı kriptosunu denetle (sadece başlık değil).

## TRANSPORT
- Zayıf protokol (SSLv3/TLS1.0/1.1), zayıf cipher (RC4/3DES/NULL/EXPORT), zayıf anahtar (<2048 RSA), zincir/expired/self-signed, hostname uyuşmazlığı.
- HSTS yok / kısa max-age / preload yok; mixed-content; downgrade.
- Araç: container'da `openssl s_client -connect host:443`, `httpx` TLS bilgisi; bulguyu somut çıktıyla göster.

## UYGULAMA KATMANI KRİPTO
- Tahmin-edilebilir token/ID (sıralı, zaman-tabanlı, zayıf rastgelelik) → oturum/parola-reset token brute/predict.
- İstemci-tarafı şifreleme (jCryption/CryptoJS) gizli anahtar gömülü → bypass (doka'da CryptoServlet/jCryption sızıntısı görülmüştü — bağla).
- Zayıf hash (MD5/SHA1 düz), tuzsuz hash; JWT `alg:none`/HS256-RS256 confusion (→ vuln-jwt-attacks).
- Sabit IV/ECB modu kalıp sızıntısı; padding-oracle (CBC) → şifre-çözme.

## KURAL
- Her bulgu GERÇEK kanıtla (openssl/httpx çıktısı, tahmin edilen token örneği). Sürüm/teori "VAR" değil — göster. Düşükse (HSTS yok) escalate ya da INFO.
