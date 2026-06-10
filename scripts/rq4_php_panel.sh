#!/usr/bin/env bash
# =============================================================================
# RQ4 PHP panel: OpenEMR security SAST agreement (source-only).
# Scoped to OpenEMR's modern PSR-4 src/ so all tools resolve symbols and are
# comparable (legacy interface/library spaghetti is a separate concern for the
# AISLE-38 recall arm; Psalm cannot analyse non-namespaced code well).
#
#   semgrep.sarif    Semgrep OSS  (p/php + p/security-audit)        — broad
#   progpilot.json   Progpilot    (PHP-specific taint)             — PHP-specific
#   psalm.sarif      Psalm --taint-analysis (GOLD-STANDARD)        — deep taint
#   bearer.sarif     Bearer                                        — sensitivity
# Headline trio mirrors Java (Semgrep+FindSecBugs+CodeQL): Semgrep+Progpilot+Psalm.
# All graceful: a failing tool is logged, others continue. Run in tmux.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNAPSHOT="$(sed -n 's/^snapshot_date:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/config/snapshot.yaml")"
OE="$ROOT/clones/github_com__openemr__openemr"
SRC="$OE/src"
OUT="$ROOT/data/raw/sast/$SNAPSHOT/php"; mkdir -p "$OUT" "$ROOT/.cache/composer"
UG="$(id -u):$(id -g)"
echo "[php] OpenEMR/src -> $OUT"

# 1) Semgrep OSS (PHP) -----------------------------------------------------------
[ -x "$ROOT/.venv/bin/semgrep" ] || uv pip install --python "$ROOT/.venv/bin/python" semgrep
if [ -s "$OUT/semgrep.sarif" ]; then echo "[php] semgrep cached"
else
  "$ROOT/.venv/bin/semgrep" scan --config p/php --config p/security-audit \
    --sarif --output "$OUT/semgrep.sarif" --metrics off --exclude .git "$SRC" \
    > "$OUT/semgrep.log" 2>&1 && echo "[php] semgrep ok" || echo "[php] semgrep FAILED"
fi

# 2) Bearer (sensitivity) --------------------------------------------------------
if [ -s "$OUT/bearer.sarif" ]; then echo "[php] bearer cached"
else
  chmod 777 "$OUT"   # bearer image runs as a non-root user; must create /out/bearer.sarif
  docker run --rm -v "$SRC:/scan:ro" -v "$OUT:/out" bearer/bearer:latest \
    scan /scan --format sarif --output /out/bearer.sarif --quiet \
    > "$OUT/bearer.log" 2>&1
  # bearer exits non-zero when findings exceed threshold; judge by SARIF presence
  [ -s "$OUT/bearer.sarif" ] && echo "[php] bearer ok" || echo "[php] bearer FAILED"
fi

# 3) Progpilot (PHP-specific taint; best-effort) ---------------------------------
if [ ! -f "$ROOT/.cache/progpilot.phar" ]; then
  URL=$(curl -s https://api.github.com/repos/designsecurity/progpilot/releases/latest \
        | grep -o 'https://[^"]*\.phar' | head -1)
  [ -n "$URL" ] && curl -sL -o "$ROOT/.cache/progpilot.phar" "$URL" || echo "[php] no progpilot phar"
fi
if [ -s "$OUT/progpilot.json" ]; then echo "[php] progpilot cached"
elif [ -f "$ROOT/.cache/progpilot.phar" ]; then
  # phar's bundled composer platform_check requires PHP >= 8.3; progpilot prints
  # JSON to stdout and exits non-zero when findings exist, so judge by content
  timeout 1800 docker run --rm -v "$SRC:/scan:ro" -v "$ROOT/.cache:/c:ro" -v "$OUT:/out" \
    php:8.3-cli sh -c 'php -d memory_limit=-1 /c/progpilot.phar /scan > /out/progpilot.json 2>/out/progpilot.err' \
    > "$OUT/progpilot.log" 2>&1
  [ -s "$OUT/progpilot.json" ] && echo "[php] progpilot ok" || echo "[php] progpilot FAILED (best-effort)"
fi

# 4) Psalm --taint-analysis (GOLD-STANDARD; composer install for symbol resolution)
#    composer image carries the PHP extensions Psalm needs (mbstring, dom, ...).
echo "[php] psalm: composer require + taint (this is the heavy step) ..."
if [ -s "$OUT/psalm.sarif" ]; then echo "[php] psalm cached"
else
timeout 5400 docker run --rm --user "$UG" -e HOME=/tmp -e COMPOSER_HOME=/tmp/composer \
  -e COMPOSER_ALLOW_SUPERUSER=1 \
  -v "$OE:/app" -v "$ROOT/.cache/composer:/tmp/composer" -v "$OUT:/out" -w /app \
  composer:2 sh -c '
    composer require --dev vimeo/psalm:^6 --no-interaction --ignore-platform-reqs \
      --with-all-dependencies --no-scripts --no-audit --no-progress 2>&1 | tail -4 || exit 11
    [ -f psalm.xml ] || ./vendor/bin/psalm --init src 3 >/dev/null 2>&1 || true
    php -d memory_limit=-1 ./vendor/bin/psalm --taint-analysis --no-cache \
      --threads=4 --no-progress --report=/out/psalm.sarif
  ' > "$OUT/psalm.log" 2>&1
  # psalm exits non-zero when taint errors are found; judge by SARIF presence
  [ -s "$OUT/psalm.sarif" ] && echo "[php] psalm ok" || echo "[php] psalm FAILED/timeout (see psalm.log)"
fi

echo "[php] done:"; ls -1 "$OUT"
