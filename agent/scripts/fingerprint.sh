#!/usr/bin/env bash
set -uo pipefail

norm_path() {
  local ep="$1"
  ep="${ep#*://}"                 # şema at
  ep="${ep%%\?*}"                 # query at
  case "$ep" in */*) ep="/${ep#*/}";; *) ep="/";; esac  # host at, path bırak
  ep="${ep%/}"; [ -z "$ep" ] && ep="/"
  printf '%s' "$ep" | sed -E \
    -e 's#/[0-9]+(/|$)#/{id}\1#g' \
    -e 's#/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/|$)#/{id}\1#g'
}
fp_of() {  # <class> <endpoint> <param>
  local cls pt par
  cls=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
  pt=$(norm_path "$2")
  par=$(printf '%s' "${3:-}" | tr '[:upper:]' '[:lower:]')
  printf '%s|%s|%s' "$cls" "$pt" "$par"
}

CMD="${1:-}"; shift || true
case "$CMD" in
  key)
    [ $# -ge 2 ] || { echo "KULLANIM: fingerprint.sh key <class> <endpoint> [param]" >&2; exit 2; }
    fp_of "$1" "$2" "${3:-}"; echo;;
  seen)
    LED="${1:-}"; [ $# -ge 3 ] || { echo "KULLANIM: fingerprint.sh seen <ledger> <class> <endpoint> [param]" >&2; exit 2; }
    FP=$(fp_of "$2" "$3" "${4:-}")
    [ -f "$LED" ] || exit 1
    grep -Fq "\"fp\":\"$FP\"" "$LED" && exit 0 || exit 1;;
  add)
    LED="${1:-}"; [ $# -ge 3 ] || { echo "KULLANIM: fingerprint.sh add <ledger> <class> <endpoint> [param] [host] [status]" >&2; exit 2; }
    CLS="$2"; EP="$3"; PAR="${4:-}"; HOST="${5:-}"; ST="${6:-confirmed}"
    FP=$(fp_of "$CLS" "$EP" "$PAR")
    mkdir -p "$(dirname "$LED")"; touch "$LED"
    if grep -Fq "\"fp\":\"$FP\"" "$LED"; then echo "ZATEN VAR: $FP"; exit 0; fi
    PT=$(norm_path "$EP")
    printf '{"fp":"%s","class":"%s","path_tpl":"%s","param":"%s","host":"%s","status":"%s"}\n' \
      "$FP" "$CLS" "$PT" "$PAR" "$HOST" "$ST" >> "$LED"
    echo "EKLENDİ: $FP";;
  *) echo "KULLANIM: fingerprint.sh {key|seen|add} ..." >&2; exit 2;;
esac
