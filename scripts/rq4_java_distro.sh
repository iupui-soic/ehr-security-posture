#!/usr/bin/env bash
# =============================================================================
# RQ4 Java panel at FULL O3-distro scope: openmrs-core + all backend omod repos.
# For each Java repo: build (Docker JDK21) -> Semgrep OSS + FindSecBugs + CodeQL.
# Per-repo SARIFs land in data/raw/sast/<snapshot>/java-distro/<repo>/.
# GRACEFUL: a repo that fails to build is logged and skipped (no silent caps);
# only repos where ALL THREE tools ran count toward the agreement universe.
# Designed to run UNATTENDED in tmux (multi-hour, build-fragile by nature).
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNAPSHOT="$(sed -n 's/^snapshot_date:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/config/snapshot.yaml")"
OUTROOT="$ROOT/data/raw/sast/$SNAPSHOT/java-distro"
M2="$ROOT/.cache/m2"; CQL="$ROOT/.cache/codeql-bundle"
IMG="maven:3.9-eclipse-temurin-21"; UG="$(id -u):$(id -g)"
COV="$OUTROOT/_coverage.tsv"
mkdir -p "$OUTROOT" "$M2"
: > "$COV"; echo -e "repo\tbuilt\tsemgrep\tfindsecbugs\tcodeql" >> "$COV"

# CodeQL bundle (cache once)
if [ ! -x "$CQL/codeql/codeql" ]; then
  mkdir -p "$CQL"
  curl -sL -o "$ROOT/.cache/codeql.tgz" \
    https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
  tar -xzf "$ROOT/.cache/codeql.tgz" -C "$CQL" && rm -f "$ROOT/.cache/codeql.tgz"
fi
# spotbugs+findsecbugs classpath (resolve once, reused for every repo)
if [ ! -s "$OUTROOT/cp.txt" ]; then
  docker run --rm --user "$UG" -e HOME=/tmp -v "$M2:/m2" -v "$ROOT/scripts:/s:ro" \
    -v "$OUTROOT:/o" "$IMG" mvn -B -ntp -q -f /s/rq4_spotbugs_pom.xml \
    -Dmaven.repo.local=/m2 dependency:build-classpath -Dmdep.outputFile=/o/cp.txt || true
fi

REPOS=$(ls -d "$ROOT"/clones/github_com__openmrs__openmrs-core \
              "$ROOT"/clones/github_com__openmrs__openmrs-module-* 2>/dev/null)

for REPO in $REPOS; do
  name="$(basename "$REPO")"
  out="$OUTROOT/$name"; mkdir -p "$out"
  built=no; sg=no; fsb=no; cq=no
  # resume: a non-empty SARIF from a previous run counts as done
  [ -s "$out/semgrep.sarif" ]     && sg=yes
  [ -s "$out/findsecbugs.sarif" ] && fsb=yes
  [ -s "$out/codeql.sarif" ]      && cq=yes

  # host-side build only feeds FindSecBugs (CodeQL traces its own build);
  # `package`, not `compile`: omod modules unpack reactor artifacts (MDEP-98).
  # JDK fallback 21->17->11->8: older modules break on newer JDKs (Lombok
  # JCTree, javax.annotation removal); maven.test.skip because stale test code
  # must not gate scanning of main code
  BIMG="$IMG"
  if [ "$fsb" = yes ]; then
    built=yes
  else
    echo "===== [$name] build ====="
    for JDK in 21 17 11 8; do
      BIMG="maven:3.9-eclipse-temurin-$JDK"
      if timeout 2400 docker run --rm --user "$UG" -e HOME=/tmp -v "$REPO:/src" -v "$M2:/m2" \
           -w /src "$BIMG" mvn -B -ntp -Dmaven.repo.local=/m2 -DskipTests \
           -Dmaven.test.skip=true clean package \
           > "$out/build.log" 2>&1; then built=yes; echo "[$name] built on JDK $JDK"; break; fi
    done
  fi

  # Semgrep (source-only; runs regardless, but only counts if repo fully covered)
  if [ "$sg" = no ]; then
    if "$ROOT/.venv/bin/semgrep" scan --config p/java --config p/security-audit \
         --config p/owasp-top-ten --sarif --output "$out/semgrep.sarif" --metrics off \
         --exclude target --exclude .git "$REPO" > "$out/semgrep.log" 2>&1; then sg=yes; fi
  fi

  if [ "$built" = yes ] && [ "$fsb" = no ]; then
    # FindSecBugs over every compiled module's classes
    CLS=$(find "$REPO" -type d -path '*/target/classes' | sed "s#$REPO#/src#" | tr '\n' ' ')
    if [ -n "$CLS" ] && timeout 900 docker run --rm --user "$UG" -e HOME=/tmp \
         -v "$REPO:/src:ro" -v "$M2:/m2" -v "$out:/o" -v "$OUTROOT/cp.txt:/cp.txt:ro" \
         -w /o "$IMG" sh -c \
         "java -cp \"\$(cat /cp.txt)\" edu.umd.cs.findbugs.LaunchAppropriateUI -textui \
            -effort:max -bugCategories SECURITY \
            -pluginList \$(find /m2 -name 'findsecbugs-plugin-*.jar'|head -1) \
            -sarif -output /o/findsecbugs.sarif $CLS" > "$out/fsb.log" 2>&1; then fsb=yes; fi
  fi

  if [ "$built" = yes ] && [ "$cq" = no ]; then
    # CodeQL traced build + security analysis
    rm -rf "$out/codeql-db"
    if timeout 3600 docker run --rm --user "$UG" -e HOME=/tmp -v "$REPO:/src" -v "$M2:/m2" \
         -v "$CQL:/codeql" -v "$out:/o" -w /src "$BIMG" sh -c \
         "/codeql/codeql/codeql database create /o/codeql-db --language=java --overwrite \
            --source-root=/src --command='mvn -B -ntp -DskipTests -Dmaven.test.skip=true -Dmaven.repo.local=/m2 clean package' && \
          /codeql/codeql/codeql database analyze /o/codeql-db \
            codeql/java-queries:codeql-suites/java-security-extended.qls \
            --format=sarif-latest --output=/o/codeql.sarif --threads=4" \
         > "$out/codeql.log" 2>&1; then cq=yes; fi
    rm -rf "$out/codeql-db"   # DBs are large; keep only SARIF
  fi
  echo -e "$name\t$built\t$sg\t$fsb\t$cq" >> "$COV"
  echo "[$name] built=$built semgrep=$sg findsecbugs=$fsb codeql=$cq"
done

echo "===== Java distro coverage ====="; column -t "$COV" 2>/dev/null || cat "$COV"
n3=$(awk -F'\t' 'NR>1 && $3=="yes" && $4=="yes" && $5=="yes"{c++} END{print c+0}' "$COV")
echo "full-3-tool repos: $n3 / $(($(wc -l < "$COV")-1))"
