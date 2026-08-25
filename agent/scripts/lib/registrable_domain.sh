#!/usr/bin/env bash

_RD_LOADED=0
declare -A _RD_EXACT _RD_WILD _RD_EXC

_rd_load() {
  [[ "$_RD_LOADED" == "1" ]] && return
  local dir; dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local psl="$dir/data/public_suffix_list.dat"
  if [[ -f "$psl" ]]; then
    local line
    while IFS= read -r line; do
      line="${line%%$'\r'}"
      [[ -z "$line" || "$line" == //* ]] && continue
      line="${line%% *}"
      case "$line" in
        '!'*) _RD_EXC["${line#!}"]=1 ;;
        '*.'*) _RD_WILD["${line#*.}"]=1 ;;
        *)    _RD_EXACT["$line"]=1 ;;
      esac
    done < "$psl"
  else
    local s
    for s in co.uk org.uk gov.uk ac.uk me.uk com.au net.au org.au gov.au edu.au \
             co.nz com.br net.br gov.br co.jp ne.jp or.jp ac.jp go.jp com.cn net.cn org.cn gov.cn \
             co.in co.za com.tr gen.tr org.tr com.mx com.ar co.kr or.kr com.sg com.hk \
             s3.amazonaws.com github.io gitlab.io herokuapp.com pages.dev web.app firebaseapp.com \
             cloudfront.net azurewebsites.net; do
      _RD_EXACT["$s"]=1
    done
  fi
  _RD_LOADED=1
}

_rd_is_suffix() { # cand → 0 (public suffix) / 1 (değil)
  local cand="$1"
  [[ -n "${_RD_EXC[$cand]:-}" ]] && return 1          # istisna: public suffix DEĞİL
  [[ -n "${_RD_EXACT[$cand]:-}" ]] && return 0
  local first="${cand%%.*}" rest="${cand#*.}"
  [[ "$first" != "$cand" && -n "${_RD_WILD[$rest]:-}" ]] && return 0
  return 1
}

registrable_domain() {
  _rd_load
  local host="${1,,}"; host="${host%.}"
  [[ -z "$host" ]] && return 1
  [[ "$host" =~ ^[0-9.]+$ ]] && { echo "$host"; return 0; }   # IP → olduğu gibi
  local IFS='.'; read -ra L <<<"$host"
  local n=${#L[@]}
  (( n<=1 )) && { echo "$host"; return 0; }
  local sl=1 i cand                                            # varsayılan TLD = 1 etiket
  for (( i=2; i<n; i++ )); do                                  # 2..n-1 etiketlik ekleri dene
    cand="$(IFS='.'; echo "${L[*]: n-i:i}")"
    _rd_is_suffix "$cand" && sl=$i                             # en uzun eşleşen kalsın
  done
  local take=$(( sl+1 )); (( take>n )) && take=$n
  echo "$(IFS='.'; echo "${L[*]: n-take:take}")"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  for h in "$@"; do printf '%s\t%s\n' "$h" "$(registrable_domain "$h")"; done
fi
