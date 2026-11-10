#!/usr/bin/env bash
# source_fetch.sh — GREY-BOX kaynak ingestion.
# Operatörün verdiği hedef kaynağını ($CYP_SOURCE_PATH: yerel dizin veya https git
# URL) çalışma alanına ($WS/source) alır, dil/stack/LOC/entrypoint özetini çıkarır
# ve $WS/source.json + $WS/source/SOURCE_SUMMARY.md yazar. surface.json varsa
# içine bir "source" bloğu birleştirir.
#
# ÖNEMLİ (sınır): yalnız OPERATÖRÜN AÇIKÇA verdiği kaynağı alır. İnternetten
# rastgele 3rd-party/OSS kaynağı KENDİLİĞİNDEN aramaz/çekmez — o hâlâ yasak
# (bkz. core-contract 3c). Bu script workspace bootstrap'ının parçasıdır.
set -uo pipefail

WS="${WS:-${CYP_FEED_DIR:-$PWD}}"
SRC="${1:-${CYP_SOURCE_PATH:-}}"
DEST="$WS/source"

if [ -z "$SRC" ]; then
  echo "SOURCE: CYP_SOURCE_PATH boş — grey-box kapalı, pure blackbox devam." >&2
  exit 0
fi

mkdir -p "$WS"

# ── 1. Ingest ────────────────────────────────────────────────────────────────
low="$(printf '%s' "$SRC" | tr '[:upper:]' '[:lower:]')"
case "$low" in
  https://*)
    echo "SOURCE: git clone (shallow) → $DEST"
    rm -rf "$DEST"
    if ! git clone --depth 1 --quiet "$SRC" "$DEST" 2>/dev/null; then
      echo "SOURCE HATA: klonlanamadı: $SRC" >&2
      exit 2
    fi
    rm -rf "$DEST/.git"
    ;;
  http://*|*://*)
    echo "SOURCE HATA: yalnız yerel yol veya https git URL desteklenir: $SRC" >&2
    exit 2
    ;;
  *)
    if [ ! -d "$SRC" ]; then
      echo "SOURCE HATA: dizin yok: $SRC" >&2
      exit 2
    fi
    echo "SOURCE: yerel kopya → $DEST"
    rm -rf "$DEST"; mkdir -p "$DEST"
    # Gürültüyü dışla (bağımlılık/derleme çıktıları) — analiz kaynağa odaklansın.
    if command -v rsync >/dev/null 2>&1; then
      rsync -a \
        --exclude '.git' --exclude 'node_modules' --exclude 'vendor' \
        --exclude 'dist' --exclude 'build' --exclude '.next' --exclude 'target' \
        --exclude '__pycache__' --exclude '*.min.js' --exclude '.venv' \
        "$SRC"/ "$DEST"/ 2>/dev/null
    else
      cp -a "$SRC"/. "$DEST"/ 2>/dev/null
      rm -rf "$DEST/.git" "$DEST/node_modules" "$DEST/vendor" "$DEST/dist" "$DEST/build" "$DEST/target" 2>/dev/null
    fi
    ;;
esac

[ -d "$DEST" ] || { echo "SOURCE HATA: ingest başarısız" >&2; exit 2; }

# ── 2. Dil / stack / LOC tespiti ─────────────────────────────────────────────
loc=$(find "$DEST" -type f \( -name '*.go' -o -name '*.js' -o -name '*.ts' -o \
  -name '*.py' -o -name '*.rb' -o -name '*.php' -o -name '*.java' -o -name '*.cs' \
  -o -name '*.rs' -o -name '*.kt' \) -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')

langs=""
add_lang() { find "$DEST" -type f -name "$1" -print -quit 2>/dev/null | grep -q . && langs="$langs $2"; }
add_lang '*.go' go; add_lang '*.ts' typescript; add_lang '*.js' javascript
add_lang '*.py' python; add_lang '*.rb' ruby; add_lang '*.php' php
add_lang '*.java' java; add_lang '*.cs' csharp; add_lang '*.rs' rust; add_lang '*.kt' kotlin
langs="$(echo "$langs" | xargs -n1 2>/dev/null | sort -u | xargs 2>/dev/null || true)"

fw=""
addfw() { [ -e "$DEST/$1" ] && fw="$fw $2"; }
addfw go.mod go-modules; addfw package.json npm; addfw requirements.txt pip
addfw pyproject.toml python-proj; addfw pom.xml maven; addfw build.gradle gradle
addfw composer.json composer; addfw Gemfile bundler; addfw Cargo.toml cargo
addfw manage.py django; addfw artisan laravel; addfw next.config.js nextjs
fw="$(echo "$fw" | xargs 2>/dev/null || true)"

# Olası giriş noktaları / route tanımları (hafif grep, derin analiz skill'in işi).
entry=$(grep -rilE 'app\.(get|post|put|delete)|@(Get|Post|RequestMapping|RestController)|router\.|http\.HandleFunc|Route::|urlpatterns' \
  "$DEST" 2>/dev/null | head -40 | sed "s#^$DEST/##" || true)

# ── 3. Çıktılar ──────────────────────────────────────────────────────────────
nfiles=$(find "$DEST" -type f 2>/dev/null | wc -l | tr -d ' ')
json_entry=$(printf '%s' "$entry" | grep -c . 2>/dev/null); json_entry="${json_entry:-0}"

jq -n --arg path "$DEST" --arg langs "$langs" --arg fw "$fw" \
  --argjson loc "${loc:-0}" --argjson files "${nfiles:-0}" --argjson entries "${json_entry:-0}" \
  '{source:{path:$path, languages:($langs|split(" ")|map(select(length>0))),
    frameworks:($fw|split(" ")|map(select(length>0))), loc:$loc, files:$files,
    entry_candidates:$entries, mode:"grey-box"}}' > "$WS/source.json" 2>/dev/null \
  || echo "{\"source\":{\"path\":\"$DEST\",\"mode\":\"grey-box\"}}" > "$WS/source.json"

{
  echo "# 🗂️ KAYNAK HARİTASI (grey-box) — $DEST"
  echo ""
  echo "> Operatör kaynağı verdi → grey-box. Kaynak HİPOTEZ üretir; KANIT hâlâ canlı"
  echo "> endpoint'te (request_id + sapma). Dış internetten kaynak çekme hâlâ YASAK."
  echo ""
  echo "- Diller: ${langs:-?}"
  echo "- Stack/manifest: ${fw:-?}"
  echo "- LOC (yaklaşık): ${loc:-?} · Dosya: ${nfiles:-?}"
  echo ""
  echo "## Olası giriş noktaları / route tanımları"
  if [ -n "$entry" ]; then printf '%s\n' "$entry" | sed 's/^/- /'; else echo "- [otomatik bulunamadı — whitebox-source-recon.md ile elle haritala]"; fi
  echo ""
  echo "## Sıradaki adım"
  echo "1. whitebox-source-recon.md: routes → auth middleware → tehlikeli sink'ler."
  echo "2. whitebox-sast.md: source→sink taint; her aday için CANLI doğrulama reçetesi."
} > "$DEST/SOURCE_SUMMARY.md"

# surface.json varsa source bloğunu birleştir (advisory).
SURF="$WS/surface.json"
if [ -f "$SURF" ] && command -v jq >/dev/null 2>&1; then
  tmp="$(mktemp 2>/dev/null || echo "$WS/.surf.tmp")"
  if jq -s '.[0] * .[1]' "$SURF" "$WS/source.json" > "$tmp" 2>/dev/null; then
    mv "$tmp" "$SURF"
  else
    rm -f "$tmp"
  fi
fi

echo "SOURCE: ingest OK — diller=[${langs:-}] loc=${loc:-0} → $WS/source.json + $DEST/SOURCE_SUMMARY.md"
