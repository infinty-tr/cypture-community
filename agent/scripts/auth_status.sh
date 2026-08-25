#!/usr/bin/env bash
if [ -n "${CYP_TEST_CREDS:-}" ]; then
  echo "Bound: operatör TEST KİMLİĞİ mevcut → Cypture ile login ol (cyp_login/cyp_create_replay_session), SESSIONID kullan. Kimlik: ${CYP_TEST_CREDS}"
else
  echo "No identities — kimlik verilmedi. Unauth yüzeyi + kendi kaydını (register) dene. ⛔ kimlik/parola UYDURMA."
fi
exit 0
