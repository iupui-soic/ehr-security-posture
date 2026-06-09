"""Lightweight dependency-manifest parsers (declared DIRECT deps; no code executed).

Syft catalogs lockfiles / installed packages; projects that declare dependencies
only in pyproject.toml (PEP 621 / Poetry), setup.py/cfg, or un-locked Gradle yield
empty/partial SBOMs. These parsers read the *declared* direct dependencies from the
source tree (statically -- nothing is built or executed) so every system has
supply-chain data. Exact-pinned versions are kept (for precise vuln matching);
range/caret constraints leave the version null (the package still counts for the
cross-system shared-dependency analysis).

Each parser yields component dicts: {name, version|None, ecosystem, purl, source_file}.
Maven pom.xml is intentionally NOT handled here -- Syft already parses it.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

# purl type per ecosystem
_PURL_TYPE = {"pypi": "pypi", "npm": "npm", "composer": "composer", "maven": "maven"}

_EXACT_PEP508 = re.compile(r"==\s*([0-9][\w.\-]*)")
_NAME_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXACT_SEMVER = re.compile(r"^\d+\.\d+(\.\d+)?$")
_GRADLE_DEP = re.compile(
    r"""(?:implementation|api|compile|compileOnly|runtimeOnly|annotationProcessor|
        testImplementation|testCompile|classpath)\s*[\s(]\s*['"]([^'"]+)['"]""",
    re.VERBOSE)


def _component(name, version, ecosystem, source_file) -> dict:
    ptype = _PURL_TYPE[ecosystem]
    purl = f"pkg:{ptype}/{name}"
    if version:
        purl += f"@{version}"
    return {"name": name, "version": version, "ecosystem": ecosystem,
            "purl": purl, "source_file": source_file}


# --- Python ---------------------------------------------------------------- #
def _pep508(spec: str) -> tuple[str, str | None] | None:
    spec = spec.split(";", 1)[0].strip()  # drop env markers
    if not spec or spec.startswith(("-", "#")):
        return None
    nm = _NAME_PEP508.match(spec)
    if not nm:
        return None
    name = nm.group(1)
    ex = _EXACT_PEP508.search(spec)
    return name.lower(), (ex.group(1) if ex else None)


def parse_pyproject(text: str, source_file: str = "pyproject.toml") -> list[dict]:
    out: list[dict] = []
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return out
    proj = doc.get("project", {})
    specs = list(proj.get("dependencies", []) or [])
    for extra in (proj.get("optional-dependencies", {}) or {}).values():
        specs.extend(extra or [])
    for spec in specs:
        p = _pep508(spec)
        if p:
            out.append(_component(p[0], p[1], "pypi", source_file))
    # Poetry style: name -> constraint dicts
    poetry = (doc.get("tool", {}) or {}).get("poetry", {}) or {}
    groups = [poetry.get("dependencies", {}) or {}]
    for g in (poetry.get("group", {}) or {}).values():
        groups.append(g.get("dependencies", {}) or {})
    for grp in groups:
        for name, constraint in grp.items():
            if name.lower() == "python":
                continue
            ver = None
            if isinstance(constraint, str) and _EXACT_SEMVER.match(constraint.lstrip("=")):
                ver = constraint.lstrip("=")
            out.append(_component(name.lower(), ver, "pypi", source_file))
    return out


def parse_requirements(text: str, source_file: str = "requirements.txt") -> list[dict]:
    out = []
    for line in text.splitlines():
        p = _pep508(line)
        if p:
            out.append(_component(p[0], p[1], "pypi", source_file))
    return out


def parse_setup_cfg(text: str, source_file: str = "setup.cfg") -> list[dict]:
    out, in_req = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"install_requires\s*=", s):
            in_req = True
            continue
        if in_req:
            if s and not line[0].isspace():
                break
            p = _pep508(s)
            if p:
                out.append(_component(p[0], p[1], "pypi", source_file))
    return out


def parse_setup_py(text: str, source_file: str = "setup.py") -> list[dict]:
    m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return []
    out = []
    for tok in re.findall(r"""['"]([^'"]+)['"]""", m.group(1)):
        p = _pep508(tok)
        if p:
            out.append(_component(p[0], p[1], "pypi", source_file))
    return out


# --- npm / composer -------------------------------------------------------- #
def _semver_exact(c: str) -> str | None:
    c = (c or "").strip()
    return c if _EXACT_SEMVER.match(c) else None


def parse_package_json(text: str, source_file: str = "package.json") -> list[dict]:
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    out = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, constraint in (doc.get(key, {}) or {}).items():
            out.append(_component(name, _semver_exact(str(constraint)), "npm", source_file))
    return out


def parse_composer_json(text: str, source_file: str = "composer.json") -> list[dict]:
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    out = []
    for key in ("require", "require-dev"):
        for name, constraint in (doc.get(key, {}) or {}).items():
            if "/" not in name:   # skip 'php', ext-*, etc.
                continue
            out.append(_component(name, _semver_exact(str(constraint)), "composer", source_file))
    return out


# --- gradle ---------------------------------------------------------------- #
def parse_gradle(text: str, source_file: str = "build.gradle") -> list[dict]:
    out = []
    for coord in _GRADLE_DEP.findall(text):
        parts = coord.split(":")
        if len(parts) < 2:
            continue
        group, artifact = parts[0], parts[1]
        ver = parts[2] if len(parts) >= 3 else None
        if ver and ("$" in ver or not ver[0].isdigit()):
            ver = None  # version via variable -> unresolved
        out.append(_component(f"{group}/{artifact}", ver, "maven", source_file))
    return out


# --- directory scan -------------------------------------------------------- #
_DISPATCH = [
    ("pyproject.toml", parse_pyproject),
    ("setup.cfg", parse_setup_cfg),
    ("setup.py", parse_setup_py),
    ("package.json", parse_package_json),
    ("composer.json", parse_composer_json),
    ("build.gradle", parse_gradle),
    ("build.gradle.kts", parse_gradle),
]
_REQ_GLOB = re.compile(r"requirements.*\.txt$", re.IGNORECASE)


def scan_clone(root: Path, max_files: int = 400) -> list[dict]:
    """Walk a clone, parse declared deps from recognised manifests, dedupe by purl."""
    root = Path(root)
    seen: dict[str, dict] = {}
    count = 0
    for path in root.rglob("*"):
        if count > max_files:
            break
        if not path.is_file() or ".git/" in str(path):
            continue
        rel = str(path.relative_to(root))
        comps: list[dict] = []
        for fname, parser in _DISPATCH:
            if path.name == fname:
                comps = parser(path.read_text(errors="ignore"), rel)
                break
        else:
            if _REQ_GLOB.search(path.name):
                comps = parse_requirements(path.read_text(errors="ignore"), rel)
        count += 1
        for c in comps:
            # exact-versioned entry wins over version-less for the same package
            key = c["purl"].split("@")[0]
            if key not in seen or (c["version"] and not seen[key]["version"]):
                seen[key] = c
    return list(seen.values())
