"""First-party source reachability for shared dependencies (RQ3 refinement).

A vulnerable *shared* dependency is a genuine cross-system single point of failure
only if the systems that ship it actually use it. We approximate call-graph
reachability with a static, language-uniform proxy: a (system, package) pair is
REACHABLE when the system either

  (a) declares the package as a direct dependency (read from the SBOM, is_direct), or
  (b) references it in first-party source (computed here by grepping the cloned
      repositories for an import / usage of the package).

Maven artifacts map to their Java import-package prefix(es); npm packages match
require()/import specifiers. node_modules / build / dist / vendored dirs are
excluded so we read application code, not bundled third-party code.

Caveat (reported in the paper): import-presence under-counts framework- and
driver-mediated use (e.g. JDBC drivers reached through the JDBC abstraction rather
than an explicit ``import org.postgresql``); the is_direct signal in (a) covers
those declared-but-not-imported cases. This is a proxy, i.e. an upper bound on
genuine call-graph reachability, not a substitute for it.
"""
from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path

from ..common import config
from ..common.logging import get_logger
from ..common.repos import parse_repo

log = get_logger("reachability")

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
_Q = "['" + '"' + "]"  # bracket class matching ' or "


def _clone_dirs(system) -> list[Path]:
    out = []
    for repo_str in system.core_repos:
        d = config.CLONES_DIR / parse_repo(repo_str).slug
        if d.exists():
            out.append(d)
    return out


def _patterns(package: str, ecosystem: str):
    if ecosystem == "maven":
        prefixes = MAVEN_IMPORT.get(package)
        if not prefixes:
            return None, None  # unknown artifact -> cannot prove a reference
        return [f"import[[:space:]]+{re.escape(p)}" for p in prefixes], JAVA_INCLUDES
    if ecosystem == "npm":
        e = re.escape(package)
        return ([f"require\\({_Q}{e}({_Q}|/)",
                 f"from[[:space:]]+{_Q}{e}({_Q}|/)",
                 f"import[[:space:]]+{_Q}{e}{_Q}",
                 f"import\\({_Q}{e}({_Q}|/)"], JS_INCLUDES)
    return None, None


def _grep_any(patterns, dirs, includes) -> bool:
    if not dirs:
        return False
    cmd = ["grep", "-rIlE", "|".join(patterns)]
    for inc in includes:
        cmd += ["--include", inc]
    for ex in EXCLUDE_DIRS:
        cmd += ["--exclude-dir", ex]
    cmd += [str(d) for d in dirs]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=420)
    except subprocess.TimeoutExpired:
        log.warning("grep timed out for %s", patterns[:1])
        return False
    return bool(res.stdout.strip())


@lru_cache(maxsize=None)
def source_referenced(system_id: str, package: str, ecosystem: str) -> bool:
    """True iff first-party source of `system_id` imports/uses `package`."""
    patterns, includes = _patterns(package, ecosystem)
    if patterns is None:
        return False
    try:
        system = config.get_system(system_id)
    except Exception:
        return False
    return _grep_any(patterns, _clone_dirs(system), includes)
