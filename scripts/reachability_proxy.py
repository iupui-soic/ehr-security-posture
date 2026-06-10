"""Import/usage reachability PROXY for the core-scope shared-vulnerable deps (F6).

For each shared-vulnerable dependency and each system that ships it, we ask a
weaker-but-honest question than full call-graph reachability: does the system's
*first-party source* actually import / reference that package?

  present  (in SBOM, current RQ3 count)  >=  referenced (this proxy)  >=  reachable (call graph)

Maven artifacts are mapped to their Java import-package prefix(es); npm packages
are matched as require()/import specifiers. node_modules/build/dist/etc. excluded.

Caveats (reported, not hidden):
 - Framework-internal Maven libs (spring-beans/-core/-context) are typically reached
   *through* the framework without an explicit application import -> this proxy
   UNDER-counts them. Treat a "no" for those as "no direct use", not "unreachable".
 - spring-web vs spring-webmvc share the org.springframework.web.* namespace and
   cannot be cleanly separated at import granularity.
 - A "yes" means the package API is named in source; it is an upper bound on
   genuine call-graph reachability, a lower bound is impossible without a call graph.
"""
import csv
import re
import subprocess
from pathlib import Path

ROOT = Path("/home/jupyter-saptpurk/bhi26-openmrs-sec1")
CLONES = ROOT / "clones"
F6 = ROOT / "paper/figures/F6_shared_vulnerable.csv"

# core-scope clone dirs per system (matches config/systems.yaml core_repos)
SYS_REPOS = {
    "ehrbase": ["github_com__ehrbase__ehrbase"],
    "openemr": ["github_com__openemr__openemr"],
    "medplum": ["github_com__medplum__medplum"],
    "openmrs": [
        "github_com__openmrs__openmrs-core",
        "github_com__openmrs__openmrs-distro-referenceapplication",
        "github_com__openmrs__openmrs-esm-core",
        "github_com__openmrs__openmrs-module-fhir2",
    ],
}

# Maven artifact -> Java import package prefix(es)
MAVEN_IMPORT = {
    "spring-beans": ["org.springframework.beans"],
    "spring-core": ["org.springframework.core"],
    "spring-context": ["org.springframework.context"],
    "spring-web": ["org.springframework.web"],
    "spring-webmvc": ["org.springframework.web.servlet"],
    "spring-boot": ["org.springframework.boot"],
    "jackson-databind": ["com.fasterxml.jackson.databind"],
    "jackson-datatype-jsr310": ["com.fasterxml.jackson.datatype.jsr310"],
    "commons-io": ["org.apache.commons.io"],
    "commons-lang3": ["org.apache.commons.lang3"],
    "postgresql": ["org.postgresql"],
    "mysql-connector-j": ["com.mysql"],
}

JAVA_INCLUDES = ["*.java", "*.kt"]
JS_INCLUDES = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"]
EXCLUDE_DIRS = [".git", "node_modules", "target", "build", "dist", "vendor",
                "out", ".gradle", "__pycache__", "coverage", "bower_components"]
Q = "['" + '"' + "]"  # bracket class matching ' or "


def grep_count(patterns, dirs, includes):
    cmd = ["grep", "-rIlE", "|".join(patterns)]
    for inc in includes:
        cmd += ["--include", inc]
    for ex in EXCLUDE_DIRS:
        cmd += ["--exclude-dir", ex]
    cmd += [str(d) for d in dirs if d.exists()]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=420)
    except subprocess.TimeoutExpired:
        return -1, None
    files = [l for l in res.stdout.splitlines() if l.strip()]
    sample = None
    if files:
        sample = files[0].replace(str(CLONES) + "/", "")
    return len(files), sample


def maven_patterns(artifact):
    return [f"import[[:space:]]+{re.escape(p)}" for p in MAVEN_IMPORT[artifact]]


def npm_patterns(pkg):
    e = re.escape(pkg)
    return [
        f"require\\({Q}{e}({Q}|/)",
        f"from[[:space:]]+{Q}{e}({Q}|/)",
        f"import[[:space:]]+{Q}{e}{Q}",
        f"import\\({Q}{e}({Q}|/)",
    ]


def main():
    rows = list(csv.DictReader(open(F6)))
    results = []
    print(f"{'package':<26}{'eco':<6}{'sev':<9}{'system':<10}{'ref?':<6}{'files':<7}sample")
    print("-" * 100)
    for r in rows:
        pkg, eco, sev = r["package"], r["ecosystem"], r["max_severity"]
        systems = [s.strip() for s in r["systems"].split(",")]
        includes = JAVA_INCLUDES if eco == "maven" else JS_INCLUDES
        patterns = maven_patterns(pkg) if eco == "maven" else npm_patterns(pkg)
        per_sys = {}
        for sid in systems:
            dirs = [CLONES / d for d in SYS_REPOS.get(sid, [])]
            n, sample = grep_count(patterns, dirs, includes)
            ref = "yes" if n > 0 else ("ERR" if n < 0 else "no")
            per_sys[sid] = (ref, n, sample)
            print(f"{pkg:<26}{eco:<6}{sev:<9}{sid:<10}{ref:<6}{str(n):<7}{sample or ''}")
        results.append((pkg, eco, sev, systems, per_sys))

    # ---- summary ----
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    any_ref = sum(1 for _, _, _, sys, ps in results
                  if any(ps[s][0] == "yes" for s in sys))
    all_ref = sum(1 for _, _, _, sys, ps in results
                  if all(ps[s][0] == "yes" for s in sys))
    none_ref = sum(1 for _, _, _, sys, ps in results
                   if all(ps[s][0] == "no" for s in sys))
    n = len(results)
    print(f"Total shared-vulnerable deps (core scope): {n}")
    print(f"  referenced by >=1 consuming system: {any_ref}/{n}")
    print(f"  referenced by ALL consuming systems: {all_ref}/{n}")
    print(f"  referenced by NONE (dead weight):    {none_ref}/{n}")

    for eco in ("maven", "npm"):
        sub = [r for r in results if r[1] == eco]
        a = sum(1 for _, _, _, sys, ps in sub if any(ps[s][0] == "yes" for s in sys))
        print(f"  [{eco}] {a}/{len(sub)} referenced by >=1 system")

    print("\nPer-system (of the shared-vuln deps it ships, how many it references):")
    for sid in SYS_REPOS:
        ships = [(pkg, ps) for pkg, _, _, sys, ps in results if sid in sys]
        refd = sum(1 for _, ps in ships if ps[sid][0] == "yes")
        if ships:
            print(f"  {sid:<10} {refd}/{len(ships)}")

    print("\nDEAD-WEIGHT candidates (present but referenced by no consuming system):")
    for pkg, eco, sev, sys, ps in results:
        if all(ps[s][0] == "no" for s in sys):
            print(f"  {pkg} ({eco}, {sev}) — ships in {', '.join(sys)}")


if __name__ == "__main__":
    main()
