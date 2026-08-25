# 🎯 KAPSAM & İZİN — [hedef]

> Bu dosya `targets/<hedef>__<tarih>/scope.md`'ye kopyalanıp doldurulur. Her istekten önce referanstır.
> Kapsam dışına İSTEK ATILMAZ. Şüphedeyse DUR ve operatöre sor. (`skills/workspace-protocol.md` §2)

```
HEDEF                      : [ana domain]
TARİH                      : [YYYY-MM-DD]

IN-SCOPE (test edilebilir) :
  - [*.hedef.com]
  - [api.hedef.com]

OUT-OF-SCOPE (DOKUNMA)     :
  - [payments.hedef.com]
  - [*.partner.com]
  - [3rd-party servisler]

İZİN / YETKİ               : [bug bounty program linki / yazılı izin / kapsam notu]
PROGRAM KURALLARI          : [rate limit, yasak testler, raporlama formatı]

KİMLİK (authenticated)     : [test kullanıcısı / token — yoksa "yok"]
ROLLER (varsa)             : [user / admin / merchant ...]

ÖZEL KISITLAR              :
  - [örn. staging'e dokunma]
  - [örn. DoS/brute yasak — zaten sistem politikası]
  - [örn. veri sızdırma yok, sadece PoC için minimal kanıt]
```

**Cypture scope:** Bu allowlist/denylist `cyp_create_scope` ile birebir kurulur (ikinci savunma hattı).
