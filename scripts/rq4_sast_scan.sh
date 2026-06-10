#!/usr/bin/env bash
# =============================================================================
# RQ4 SAST agreement scan (Java panel) — reproducible companion to
# src/analyze/sast_agreement.py.
#
# Builds a Maven module and runs three OPEN security SAST tools over it, emitting
# SARIF into data/raw/sast/<snapshot>/:
#   semgrep.sarif      Semgrep OSS  (security rule packs; source-only)
#   findsecbugs.sarif  SpotBugs + FindSecBugs (SECURITY category; on bytecode)
#   codeql.sarif       CodeQL java-security-extended (traced build)
# If SEMGREP_APP_TOKEN is set, also emits semgrep_pro.sarif (Pro interfile engine,
# AI Assistant NOT invoked) as a non-reproducible *sensitivity* arm.
#
# JDK21 + Maven + the tools all run via Docker (host needs only Docker + the .venv
# semgrep). Caches (Maven repo, CodeQL bundle) live under .cache/ (gitignored).
# Aggregate-only by design (DISCLOSURE.md Construct E).
#
# Usage:  bash scripts/rq4_sast_scan.sh            # defaults: openmrs-core / api
#         CLONE=<dir> MODULE=<m> bash scripts/rq4_sast_scan.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNAPSHOT="$(sed -n 's/^snapshot_date:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/config/snapshot.yaml")"
CLONE="${CLONE:-$ROOT/clones/github_com__openmrs__openmrs-core}"
MODULE="${MODULE:-api}"
OUT="$ROOT/data/raw/sast/$SNAPSHOT"
M2="$ROOT/.cache/m2"
CQL="$ROOT/.cache/codeql-bundle"
MVN_IMG="maven:3.9-eclipse-temurin-21"
UG="$(id -u):$(id -g)"
mkdir -p "$OUT" "$M2" "$CQL"
echo "[rq4] snapshot=$SNAPSHOT  module=$MODULE  clone=$CLONE  ->  $OUT"

run() { echo "+ $*"; "$@"; }

# 0) compile the module (JDK21) — produces bytecode for FindSecBugs ---------------
run docker run --rm --user "$UG" -e HOME=/tmp -v "$CLONE:/src" -v "$M2:/m2" -w /src \
  "$MVN_IMG" mvn -B -ntp -Dmaven.repo.local=/m2 -DskipTests -pl "$MODULE" -am compile

# 1) Semgrep OSS (security rule packs; source-only) ------------------------------
[ -x "$ROOT/.venv/bin/semgrep" ] || uv pip install --python "$ROOT/.venv/bin/python" semgrep
run "$ROOT/.venv/bin/semgrep" scan --config p/java --config p/security-audit \
  --config p/owasp-top-ten --sarif --output "$OUT/semgrep.sarif" --metrics off \
  --exclude target --exclude .git "$CLONE/$MODULE/src/main/java" || true

# 1b) Semgrep Pro sensitivity arm (interfile engine; AI off) — token-gated --------
TOKEN="${SEMGREP_APP_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$ROOT/.env" ]; then
  TOKEN="$(grep -E '^SEMGREP_APP_TOKEN=' "$ROOT/.env" | head -1 | cut -d= -f2-)"
  TOKEN="${TOKEN%\"}"; TOKEN="${TOKEN#\"}"; TOKEN="${TOKEN%\'}"; TOKEN="${TOKEN#\'}"
  TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"
fi
if [ -n "$TOKEN" ]; then
  echo "[rq4] SEMGREP_APP_TOKEN present -> Pro sensitivity scan (AI off)"
  run env SEMGREP_APP_TOKEN="$TOKEN" "$ROOT/.venv/bin/semgrep" scan --pro \
    --config p/java --config p/security-audit --config p/owasp-top-ten \
    --sarif --output "$OUT/semgrep_pro.sarif" --metrics off \
    --exclude target --exclude .git "$CLONE/$MODULE/src/main/java" || true
fi

# 2) SpotBugs + FindSecBugs (SECURITY category) on the compiled bytecode ----------
run docker run --rm --user "$UG" -e HOME=/tmp -v "$CLONE:/src:ro" -v "$M2:/m2" \
  -v "$ROOT/scripts:/scripts:ro" -v "$OUT:/out" -w /out "$MVN_IMG" sh -c '
    mvn -B -ntp -q -f /scripts/rq4_spotbugs_pom.xml -Dmaven.repo.local=/m2 \
        dependency:build-classpath -Dmdep.outputFile=/out/cp.txt
    FSB=$(find /m2 -name "findsecbugs-plugin-*.jar" | head -1)
    java -cp "$(cat /out/cp.txt)" edu.umd.cs.findbugs.LaunchAppropriateUI -textui \
      -effort:max -bugCategories SECURITY -pluginList "$FSB" \
      -sarif -output /out/findsecbugs.sarif "/src/'"$MODULE"'/target/classes"
  '

# 3) CodeQL (traced clean build + java-security-extended) -------------------------
if [ ! -x "$CQL/codeql/codeql" ]; then
  echo "[rq4] fetching CodeQL CLI bundle (cached in .cache/) ..."
  curl -sL -o "$ROOT/.cache/codeql.tgz" \
    https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
  tar -xzf "$ROOT/.cache/codeql.tgz" -C "$CQL" && rm -f "$ROOT/.cache/codeql.tgz"
fi
rm -rf "$OUT/codeql-db"
run docker run --rm --user "$UG" -e HOME=/tmp -v "$CLONE:/src" -v "$M2:/m2" \
  -v "$CQL:/codeql" -v "$OUT:/out" -w /src "$MVN_IMG" sh -c '
    /codeql/codeql/codeql database create /out/codeql-db --language=java --overwrite \
      --source-root=/src \
      --command="mvn -B -ntp -pl '"$MODULE"' -am -DskipTests -Dmaven.repo.local=/m2 clean compile"
    /codeql/codeql/codeql database analyze /out/codeql-db \
      codeql/java-queries:codeql-suites/java-security-extended.qls \
      --format=sarif-latest --output=/out/codeql.sarif --threads=4
  '

echo "[rq4] done. SARIF in $OUT:"
ls -1 "$OUT"/*.sarif 2>/dev/null
for f in semgrep findsecbugs codeql; do
  [ -f "$OUT/$f.sarif" ] || { echo "[rq4] ERROR: missing $f.sarif"; exit 1; }
done
