"""RQ4 spine: inter-tool SAST agreement (Fleiss' kappa + ICC), three modes.

Normalises every finding to a source file, and reports per-tool counts, pairwise
overlap, Fleiss' kappa (per-file flag) and ICC(2,1) on per-file counts. The point
is methodological: how much do independent strong SAST tools agree? Low agreement
=> single-tool "density" is not a reliable posture signal.

--mode module (default; companion to scripts/rq4_sast_scan.sh)
  Single built Maven module (pilot: openmrs-core/api). Panel:
  - semgrep.sarif     Semgrep OSS  (security configs)        key: <module>/src/main/java/
  - findsecbugs.sarif SpotBugs+FindSecBugs (SECURITY only)   key: package-relative
  - codeql.sarif      CodeQL java-security-extended          key: <module>/src/main/java/

--mode java-distro (companion to scripts/rq4_java_distro.sh)
  Same Java panel pooled over every O3-distro repo with FULL 3-tool coverage
  (a repo missing any SARIF is excluded and listed, no silent caps). Universe =
  main-source .java files (any */src/main/java/), keys repo-prefixed. FindSecBugs
  URIs are package-relative; mapped to the first (sorted) module containing that
  path -- a documented approximation for multi-module repos.

--mode php (companion to scripts/rq4_php_panel.sh)
  OpenEMR src/ (PSR-4 scope). Headline trio mirrors the Java panel:
  - semgrep.sarif     Semgrep OSS (p/php + p/security-audit)  broad pattern
  - progpilot.json    Progpilot                               PHP-specific taint
  - psalm.sarif       Psalm --taint-analysis                  deep taint
  bearer.sarif joins the 4-rater sensitivity panel. Missing raters are dropped
  and reported (panel composition is recorded in the CSV).

Reported AGGREGATE only (DISCLOSURE.md Construct E): counts + agreement stats, no
per-finding file:line detail.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

from ..common.logging import get_logger

log = get_logger("sast_agreement")

# (display name, sarif filename, key mode, restrict-to-security)
PANEL = [
    ("semgrep", "semgrep.sarif", "src_main_java", False),
    ("findsecbugs", "findsecbugs.sarif", "package_rel", False),
    ("codeql", "codeql.sarif", "src_main_java", True),
]


def _rule_is_security(rule: dict) -> bool:
    props = rule.get("properties", {}) or {}
    tags = props.get("tags", []) or []
    return ("security-severity" in props) or any(
        t.startswith("external/cwe") or t == "security" for t in tags)


def _findings(sarif: Path, key_mode: str, module: str, universe: set,
              security_only: bool):
    """Return Counter {package_rel_file: n_findings}."""
    import collections
    out = collections.Counter()
    if not sarif.exists():
        log.warning("missing SARIF: %s", sarif)
        return out
    data = json.loads(sarif.read_text())
    marker = f"{module}/src/main/java/"
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in
                 run.get("tool", {}).get("driver", {}).get("rules", [])}
        for x in run.get("results", []):
            if security_only and not _rule_is_security(rules.get(x.get("ruleId", ""), {})):
                continue
            uri = ((x.get("locations") or [{}])[0].get("physicalLocation", {})
                   .get("artifactLocation", {}).get("uri", "")).replace("file://", "")
            if key_mode == "src_main_java":
                key = uri.split(marker, 1)[1] if marker in uri else None
            else:  # package_rel: uri already package-relative
                key = uri if uri in universe else None
            if key:
                out[key] += 1
    return out


def _sarif_counter(sarif: Path, keyfn, security_only: bool = False):
    """Counter {key: n_findings} from a SARIF file; None if the file is absent."""
    import collections
    if not sarif.exists() or sarif.stat().st_size == 0:
        return None
    out = collections.Counter()
    data = json.loads(sarif.read_text())
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in
                 run.get("tool", {}).get("driver", {}).get("rules", [])}
        for x in run.get("results", []):
            if security_only and not _rule_is_security(rules.get(x.get("ruleId", ""), {})):
                continue
            uri = ((x.get("locations") or [{}])[0].get("physicalLocation", {})
                   .get("artifactLocation", {}).get("uri", "")).replace("file://", "")
            key = keyfn(uri)
            if key:
                out[key] += 1
    return out


def _agreement(universe: set, counts: dict) -> dict:
    """Shared metric block: overlap, Jaccard, Fleiss' kappa, ICC(2,1)."""
    names = list(counts)
    m = len(names)
    sets = {nm: set(c) for nm, c in counts.items()}
    union = set().union(*sets.values()) if sets else set()
    allflag = set.intersection(*sets.values()) if sets else set()
    per_item = np.array([sum(1 for s in sets.values() if f in s) for f in universe])
    fleiss = _fleiss_kappa(per_item, m) if m > 1 else float("nan")
    files = sorted(union)
    M = np.array([[counts[nm].get(f, 0) for nm in names] for f in files], dtype=float)
    icc = _icc21(M) if len(files) > 1 and m > 1 else float("nan")

    def jac(a, b):
        u = len(sets[a] | sets[b])
        return len(sets[a] & sets[b]) / u if u else 0.0

    return {
        "panel": "+".join(names), "universe_files": len(universe),
        "findings": {nm: int(sum(counts[nm].values())) for nm in names},
        "files_flagged": {nm: len(sets[nm]) for nm in names},
        "all_rater_overlap": len(allflag), "union_files": len(union),
        "jaccard_all": round(len(allflag) / len(union), 4) if union else 0.0,
        "pairwise_jaccard": {f"{a}-{b}": round(jac(a, b), 4)
                             for i, a in enumerate(names) for b in names[i + 1:]},
        "fleiss_kappa": round(fleiss, 4), "icc_2_1": round(icc, 4),
    }


def compute_java_distro(clones_root: Path, sarif_root: Path) -> dict:
    """Pool the Java panel over every distro repo with full 3-tool coverage."""
    import collections
    panel = [("semgrep", False), ("findsecbugs", False), ("codeql", True)]
    counts = {nm: collections.Counter() for nm, _ in panel}
    universe: set = set()
    covered, skipped = [], []
    for sdir in sorted(p for p in sarif_root.iterdir() if p.is_dir()):
        repo = sdir.name
        sarifs = {nm: sdir / f"{nm}.sarif" for nm, _ in panel}
        if not all(f.exists() and f.stat().st_size for f in sarifs.values()):
            skipped.append(repo)
            continue
        clone = clones_root / repo
        repo_files = sorted(p.relative_to(clone).as_posix() for p in clone.rglob("*.java")
                            if "src/main/java/" in p.relative_to(clone).as_posix())
        pkg_map: dict = {}
        for rel in repo_files:
            pkg_map.setdefault(rel.split("src/main/java/", 1)[1], rel)

        def keyfn(uri, repo=repo, pkg_map=pkg_map):
            pkg = (uri.split("src/main/java/", 1)[1]
                   if "src/main/java/" in uri else uri)  # findsecbugs: package-rel
            rel = pkg_map.get(pkg)
            return f"{repo}/{rel}" if rel else None

        for nm, sec in panel:
            counts[nm].update(_sarif_counter(sarifs[nm], keyfn, sec))
        universe |= {f"{repo}/{rel}" for rel in repo_files}
        covered.append(repo)
    r = _agreement(universe, counts)
    r.update({"covered_repos": len(covered), "skipped_repos": len(skipped),
              "skipped_list": ";".join(skipped)})
    return r


def _php_keyfn(universe: set):
    def keyfn(uri):
        u = uri[6:] if uri.startswith("/scan/") else uri
        if u in universe:
            return u
        if u.startswith("src/") and u[4:] in universe:  # psalm: openemr-root-relative
            return u[4:]
        i = 0
        while True:  # absolute host path: try the tail after each /src/
            i = u.find("/src/", i)
            if i < 0:
                return None
            if u[i + 5:] in universe:
                return u[i + 5:]
            i += 1
    return keyfn


def _progpilot_counter(path: Path, keyfn):
    """Progpilot emits a JSON list; count one (sink) file per finding."""
    import collections
    if not path.exists() or path.stat().st_size == 0:
        return None
    out = collections.Counter()
    for f in json.loads(path.read_text()):
        v = f.get("sink_file") or f.get("vuln_file")
        for u in (v if isinstance(v, list) else [v]):
            key = keyfn(u) if u else None
            if key:
                out[key] += 1
                break
    return out


def compute_php(src: Path, sarif_dir: Path) -> dict:
    """OpenEMR src/ panel; headline trio + 4-rater sensitivity (bearer)."""
    universe = {p.relative_to(src).as_posix() for p in src.rglob("*.php")}
    keyfn = _php_keyfn(universe)
    raters = {
        "semgrep": _sarif_counter(sarif_dir / "semgrep.sarif", keyfn),
        "progpilot": _progpilot_counter(sarif_dir / "progpilot.json", keyfn),
        "psalm": _sarif_counter(sarif_dir / "psalm.sarif", keyfn),
        "bearer": _sarif_counter(sarif_dir / "bearer.sarif", keyfn),
    }
    missing = sorted(nm for nm, c in raters.items() if c is None)
    avail = {nm: c for nm, c in raters.items() if c is not None}
    trio = {nm: avail[nm] for nm in ("semgrep", "progpilot", "psalm") if nm in avail}
    r = _agreement(universe, trio)
    if "bearer" in avail:
        r["sensitivity_4rater"] = _agreement(universe, avail)
    r["missing_raters"] = ";".join(missing)
    return r


def _fleiss_kappa(per_item_positive: np.ndarray, m: int) -> float:
    """Binary Fleiss' kappa: per_item_positive = #raters flagging each item."""
    n = len(per_item_positive)
    Pi = ((per_item_positive ** 2 + (m - per_item_positive) ** 2) - m) / (m * (m - 1))
    Pbar = Pi.mean()
    p1 = per_item_positive.sum() / (n * m)
    Pe = p1 ** 2 + (1 - p1) ** 2
    return float((Pbar - Pe) / (1 - Pe)) if Pe < 1 else float("nan")


def _icc21(M: np.ndarray) -> float:
    """ICC(2,1), two-way random, single rater, absolute agreement."""
    n, k = M.shape
    gm = M.mean()
    MSR = k * ((M.mean(1) - gm) ** 2).sum() / (n - 1)
    MSC = n * ((M.mean(0) - gm) ** 2).sum() / (k - 1)
    MSE = ((M - M.mean(1, keepdims=True) - M.mean(0, keepdims=True) + gm) ** 2
           ).sum() / ((n - 1) * (k - 1))
    return float((MSR - MSE) / (MSR + (k - 1) * MSE + (k / n) * (MSC - MSE)))


def compute(clone: Path, module: str, sarif_dir: Path) -> dict:
    src = clone / module / "src" / "main" / "java"
    universe = {str(p.relative_to(src)) for p in src.rglob("*.java")}
    N = len(universe)
    counts = {name: _findings(sarif_dir / fn, mode, module, universe, sec)
              for name, fn, mode, sec in PANEL}
    sets = {name: set(c) for name, c in counts.items()}
    names = [p[0] for p in PANEL]
    m = len(names)

    union = set().union(*sets.values())
    allflag = set.intersection(*sets.values()) if sets else set()
    per_item = np.array([sum(1 for s in sets.values() if f in s) for f in universe])
    fleiss = _fleiss_kappa(per_item, m)
    files = sorted(union)
    M = np.array([[counts[nm].get(f, 0) for nm in names] for f in files], dtype=float)
    icc = _icc21(M) if len(files) > 1 else float("nan")

    def jac(a, b):
        u = len(sets[a] | sets[b])
        return len(sets[a] & sets[b]) / u if u else 0.0

    return {
        "module": module, "universe_files": N,
        "findings": {nm: int(sum(counts[nm].values())) for nm in names},
        "files_flagged": {nm: len(sets[nm]) for nm in names},
        "all_three_overlap": len(allflag), "union_files": len(union),
        "jaccard_3way": round(len(allflag) / len(union), 4) if union else 0.0,
        "pairwise_jaccard": {f"{a}-{b}": round(jac(a, b), 4)
                             for i, a in enumerate(names) for b in names[i + 1:]},
        "fleiss_kappa": round(fleiss, 4), "icc_2_1": round(icc, 4),
    }


def _flat_rows(r: dict, prefix: str = ""):
    """Flatten a result dict into (metric, value) CSV rows."""
    rows = []
    for k, v in r.items():
        if k in ("findings", "files_flagged"):
            rows += [(f"{prefix}{k}_{nm}", n) for nm, n in v.items()]
        elif k == "pairwise_jaccard":
            rows += [(f"{prefix}jaccard_{pair}", n) for pair, n in v.items()]
        elif k == "sensitivity_4rater":
            rows += _flat_rows(v, prefix="all4_")
        else:
            rows.append((f"{prefix}{k}", v))
    return rows


def _report(r: dict, out_path: str | None) -> None:
    log.info("panel=%s | universe=%d | findings=%s | files=%s", r.get("panel"),
             r["universe_files"], r["findings"], r["files_flagged"])
    log.info("all-rater overlap=%d / union=%d | Jaccard=%.4f | pairwise=%s",
             r["all_rater_overlap"], r["union_files"], r["jaccard_all"],
             r["pairwise_jaccard"])
    log.info("Fleiss kappa=%.4f | ICC(2,1)=%.4f", r["fleiss_kappa"], r["icc_2_1"])
    if out_path:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["metric", "value"])
            w.writerows(_flat_rows(r))
        log.info("wrote %s", out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["module", "java-distro", "php"],
                    default="module")
    ap.add_argument("--clone", help="[module] path to the cloned repo")
    ap.add_argument("--module", default="api", help="[module] Maven module")
    ap.add_argument("--sarif-dir", help="[module|php] dir with the SARIF files")
    ap.add_argument("--clones-root", default="clones", help="[java-distro] clones dir")
    ap.add_argument("--sarif-root", help="[java-distro] per-repo SARIF root")
    ap.add_argument("--php-src", help="[php] scanned source dir (OpenEMR src/)")
    ap.add_argument("--out", help="CSV summary output path")
    a = ap.parse_args()
    if a.mode == "java-distro":
        if not a.sarif_root:
            ap.error("--mode java-distro requires --sarif-root")
        r = compute_java_distro(Path(a.clones_root), Path(a.sarif_root))
        log.info("repos: covered=%d skipped=%d %s", r["covered_repos"],
                 r["skipped_repos"], r["skipped_list"] or "")
    elif a.mode == "php":
        if not (a.php_src and a.sarif_dir):
            ap.error("--mode php requires --php-src and --sarif-dir")
        r = compute_php(Path(a.php_src), Path(a.sarif_dir))
        if r["missing_raters"]:
            log.warning("missing raters: %s", r["missing_raters"])
    else:
        if not (a.clone and a.sarif_dir):
            ap.error("--mode module requires --clone and --sarif-dir")
        r = compute(Path(a.clone), a.module, Path(a.sarif_dir))
        # unify pilot key names with the shared reporter
        r["all_rater_overlap"] = r.pop("all_three_overlap")
        r["jaccard_all"] = r.pop("jaccard_3way")
        r.setdefault("panel", "semgrep+findsecbugs+codeql")
    _report(r, a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
