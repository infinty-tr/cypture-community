# KİMLİK EDİNME (auth-gated testler için kendi hesabını aç)

Goal 1: sistem kimlik İSTEMEZ — kendi açar. Auth arkası testler (IDOR/BOLA/BFLA, session, account-takeover)
en az bir, IDOR için **iki** kimlik ister. Akış best-effort'tur: **başarısız olsa bile DURMA**, diğer sınıflara devam.

## Akış
1. `bash scripts/acquire_identity.sh <surf> <host> user` → pending slot + benzersiz email/parola + reçete.
2. **Register** (Cypture ile, curl YASAK): recon/surface'tan register endpoint'ini bul (`/register`, `/signup`,
   `/api/v1/users`, GraphQL `signup` mutation). `cyp_send_request` ile üretilen email/parola'yı POST et.
3. **Login** → `Set-Cookie`/token al → `cyp_create_replay_session` veya `cyp_set_session_request` ile
   Cypture session'ı oluştur. Session id'yi al.
4. `bash scripts/mark_identity.sh <surf> <host> <handle> <cyp_session> user` → "acquired".
5. IDOR için 2. kez: `acquire_identity.sh <surf> <host> user2` → register/login → `mark_identity.sh ... user2`.
   İki acquired kimlik → `diff_idor.sh` A (sahip) / B (saldırgan) ile çalışır.

## Engeller (fallback)
- **CAPTCHA**: otomatik çözme YOK. Operatöre bildir; varsa sağlanan test kimliğini `mark_identity.sh` ile gir.
  Yoksa o host'ta auth-gated sınıfları "uygulanamaz" işaretle, diğerlerine devam (best-effort).
- **E-posta doğrulaması**: operatör doğrulanabilir kutu sağlamadıysa, magic-link/again token akışını dene;
  olmazsa engeli net raporla, devam et.
- **Davet-only / ödeme duvarı**: kapsam dışıysa atla; içindeyse operatöre kimlik iste, bu arada unauth yüzeyi tüket.

## Kanıt
Edinilen her kimlik Cypture'da loglanır (register+login request_id'leri). IDOR bulgusunda baseline_req (A) ve
deviation_req (B) bu kimliklerin istekleridir → `validate_finding.sh` kıyas-tabanlı tip için baseline ister.
