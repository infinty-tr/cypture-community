#!/usr/bin/env bash
set -euo pipefail

PLATFORM="${1:-}"; HANDLE="${2:-}"; OUTDIR="${3:-}"
if [[ -z "$PLATFORM" || -z "$HANDLE" || -z "$OUTDIR" ]]; then
  echo "KULLANIM: scope_fetch.sh <hackerone|bugcrowd|intigriti|yeswehack> <handle> <output_dir>" >&2
  exit 2
fi
command -v jq   >/dev/null || { echo "HATA: jq gerekli (sudo pacman -S jq)" >&2; exit 3; }
command -v curl >/dev/null || { echo "HATA: curl gerekli" >&2; exit 3; }
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/registrable_domain.sh"
mkdir -p "$OUTDIR"

BASE="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
case "$PLATFORM" in
  hackerone) URL="$BASE/hackerone_data.json" ;;
  bugcrowd)  URL="$BASE/bugcrowd_data.json" ;;
  intigriti) URL="$BASE/intigriti_data.json" ;;
  yeswehack) URL="$BASE/yeswehack_data.json" ;;
  *) echo "HATA: bilinmeyen platform '$PLATFORM'" >&2; exit 2 ;;
esac

CACHE="/tmp/btd_${PLATFORM}.json"
if [[ ! -f "$CACHE" ]] || [[ $(find "$CACHE" -mmin +720 2>/dev/null) ]]; then
  curl -fsSL "$URL" -o "$CACHE" || { echo "HATA: veri seti indirilemedi ($URL)" >&2; exit 4; }
fi

PROG=$(jq --arg h "$HANDLE" '
  [ .[] | select(((.handle // .name // "") | ascii_downcase) | contains($h | ascii_downcase)) ] | .[0]
' "$CACHE")

if [[ "$PROG" == "null" || -z "$PROG" ]]; then
  echo "BULUNAMADI: '$HANDLE' programı $PLATFORM veri setinde yok. Handle'ı kontrol et." >&2
  exit 5
fi

NAME=$(echo "$PROG" | jq -r '.name // .handle // "?"')

INSCOPE=$(echo "$PROG"  | jq -r '(.targets.in_scope  // []) | .[] | ((.asset_type // .type // "?")|ascii_upcase)+"\t"+(.asset_identifier // .target // .url // empty)')
OUTSCOPE=$(echo "$PROG" | jq -r '(.targets.out_of_scope // []) | .[] | (.asset_identifier // .target // .url // empty)' | sort -u)

WEB_RE='^(URL|WILDCARD|CIDR|IP_ADDRESS|API|WEBSITE)$'
HOSTS=$(echo "$INSCOPE" | awk -F'\t' -v re="$WEB_RE" 'toupper($1) ~ re {print $2}' \
        | sed -E 's#^[a-z]+://##; s#/.*$##; s/^\*\.//; s/^\*//' | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' | sort -u || true)
NONWEB=$(echo "$INSCOPE" | awk -F'\t' -v re="$WEB_RE" 'toupper($1) !~ re {print $1": "$2}' | sort -u || true)
INSCOPE_ALL=$(echo "$INSCOPE" | awk -F'\t' '{print $1": "$2}' | sort -u)

OUTHOSTS=$(echo "$OUTSCOPE" | sed -E 's#^[a-z]+://##; s#/.*$##; s/^\*\.//' | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' || true)
ROOTS=$(while IFS= read -r h; do [[ -n "$h" ]] && registrable_domain "$h"; done \
        < <(printf '%s\n%s\n' "$HOSTS" "$OUTHOSTS" | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$') | sort -u || true)

{
  echo "# 🎯 KAPSAM & İZİN — $NAME"
  echo ""
  echo "> OTOMATİK ÇEKİLDİ: $PLATFORM / '$HANDLE' (kaynak: bounty-targets-data). Doğrula, gerekirse düzelt."
  echo ""
  echo '```'
  echo "HEDEF                      : $NAME"
  echo "PLATFORM                   : $PLATFORM"
  echo ""
  echo "IN-SCOPE — WEB/API (test edilebilir) :"
  if [[ -n "$HOSTS" ]]; then echo "$HOSTS" | sed 's/^/  - /'; else echo "  - [web/API host yok — aşağıdaki web-dışı varlıklara bak]"; fi
  echo ""
  echo "IN-SCOPE — WEB DIŞI (mobil/source/hardware — web/API testine GİRMEZ):"
  if [[ -n "$NONWEB" ]]; then echo "$NONWEB" | sed 's/^/  - /'; else echo "  - [yok]"; fi
  echo ""
  echo "OUT-OF-SCOPE (DOKUNMA)     :"
  if [[ -n "$OUTSCOPE" ]]; then echo "$OUTSCOPE" | sed 's/^/  - /'; else echo "  - [belirtilmemiş]"; fi
  echo ""
  echo "İZİN / YETKİ               : $PLATFORM programı ($HANDLE) — program kurallarına UY"
  echo "KİMLİK (authenticated)     : [varsa test kullanıcısı/token — yoksa yok]"
  echo "ÖZEL KISITLAR              : [program politikası: rate limit, yasak testler]"
  echo '```'
} > "$OUTDIR/scope.md"

echo "PROGRAM    : $NAME ($PLATFORM)"
echo "WEB/API    : $(echo "$HOSTS"   | grep -c . || true) host (test edilebilir)"
echo "WEB-DIŞI   : $(echo "$NONWEB"  | grep -c . || true) varlık (mobil/source/hw — atlanır)"
echo "OUT-SCOPE  : $(echo "$OUTSCOPE" | grep -c . || true) varlık"
echo "SCOPE.MD   : $OUTDIR/scope.md yazıldı"
echo "--- RECON + CYPTURE SCOPE İÇİN WEB/API HOSTNAME'LER (garanti in-scope) ---"
echo "$HOSTS"
echo "--- KÖK DOMAIN(LER) — açık/dışlama-tabanlı scope'ta subdomain enumeration buradan ---"
echo "$ROOTS"
echo "═══ SCOPE MODELİ KARARI (operatör + policy belirler) ═══"
echo "Structured veri: $(echo "$HOSTS"|grep -c .) in-scope host, $(echo "$OUTSCOPE"|grep -c .) out-of-scope, wildcard yok-gibi."
echo "  • KATI (strict): policy SADECE yukarıdaki host'ları listeliyorsa → yalnız onları test et."
echo "  • AÇIK (open/dışlama): policy 'out-of-scope dışında her şey' / 'tüm *.domain' diyorsa → KÖK domain'leri"
echo "    enumerate et (subfinder/amass/crt.sh), OUT-OF-SCOPE'u ÇIKAR, gerisinin TAMAMINI test et."
echo "  → 'full scan' komutu + broad policy = AÇIK mod. Emin değilsen H1 policy metnini OKU, sonra karar ver."
