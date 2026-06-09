"""Acquire the OpenMRS "O3 reference-application as shipped" dependency surface
for the RQ3 supply-chain sensitivity check (the wider-scope arm).

The core scope (config/systems.yaml -> openmrs.core_repos) Syfts only openmrs-core,
the distro, esm-core, and module-fhir2 — a small slice of what the O3 reference
application docker image actually ships. This module enumerates the shipped set
from the distro's own assembly files and produces a Syft SBOM per backing source
repo, so analyze/o3_sensitivity.py can union them into an `openmrs_wide` node set.

Why Syft, not deps.dev: deps.dev has no resolved dependency graph for the
@openmrs/esm-*-app npm packages (returns a SELF-only node) and does not index the
org.openmrs.module Maven (O)MODs at all. Syft-on-clone is the pipeline's standard
SBOM tool and applies uniformly here. The distro pins frontend modules to the
moving `next` (pre-release) dist-tag; we clone each source repo's default branch,
which tracks that same development line, and record the resolution for provenance.

Source of truth (archived under data/raw/o3wide/<date>/ for provenance):
  * frontend/spa-assemble-config.json  -> @openmrs/esm-*-app packages
  * distro/distro.properties           -> omod.* backend modules
Frontend packages map to their GitHub source repo via the npm registry's
`repository.url`; backend modules to openmrs/openmrs-module-<name>. Repos that do
not resolve or clone are logged to the manifest (never fabricated).

Runs after the core pipeline. Needs Docker (Syft) + network; GITHUB_TOKEN optional.
"""
from __future__ import annotations

import argparse
import json

import requests

from ..common import config, provenance
from ..common.clone import ensure_clone
from ..common.http import Client, RateLimiter
from ..common.logging import get_logger
from ..common.repos import Repo, parse_repo
from .sbom_generate import _ensure_image, _merge_manifest_deps, _run_syft, SYFT_IMAGE

log = get_logger("o3_wide")
SOURCE = "o3wide"
SBOM_SOURCE = "sbom"

DISTRO = "openmrs/openmrs-distro-referenceapplication"
ASSEMBLE_PATH = "frontend/spa-assemble-config.json"
PROPS_PATH = "distro/distro.properties"

# distro.properties keys that are attributes of an omod entry, not modules.
_OMOD_ATTR_SUFFIXES = (".groupId", ".artifactId", ".type", ".version")


def _npm_client() -> Client:
    return Client(base_url="", rate=RateLimiter(0.1))


def _repo_from_npm_url(url: str | None) -> Repo | None:
    """Normalise an npm `repository.url` (git+https://…/x.git#branch) to a Repo."""
    if not url or "github.com" not in url:
        return None
    s = url.strip()
    for pfx in ("git+", "git:"):
        if s.startswith(pfx):
            s = s[len(pfx):]
    s = s.split("#", 1)[0]
    if s.endswith(".git"):
        s = s[:-4]
    try:
        return parse_repo(s)
    except (IndexError, ValueError):
        return None


def _read_distro_file(distro_path, rel_path: str) -> str:
    return (distro_path / rel_path).read_text()


def _resolve_frontend(assemble_text: str, npm: Client) -> tuple[dict[str, Repo], dict, list]:
    cfg = json.loads(assemble_text)
    pkgs = list((cfg.get("frontendModules") or {}).keys())
    repos: dict[str, Repo] = {}
    pkg_map: dict[str, str | None] = {}
    unresolved: list[dict] = []
    for pkg in pkgs:
        url = None
        try:
            meta = npm.get_json(f"https://registry.npmjs.org/{pkg}")
            rep = meta.get("repository") or {}
            url = rep.get("url") if isinstance(rep, dict) else rep
        except (requests.RequestException, ValueError) as exc:
            log.warning("npm lookup failed for %s: %s", pkg, exc)
        repo = _repo_from_npm_url(url)
        if repo is None:
            pkg_map[pkg] = None
            unresolved.append({"kind": "frontend", "package": pkg, "repository_url": url})
        else:
            pkg_map[pkg] = repo.full_name
            repos[repo.full_name] = repo
    return repos, pkg_map, unresolved


def _resolve_backend(props_text: str) -> tuple[dict[str, Repo], dict]:
    repos: dict[str, Repo] = {}
    mod_map: dict[str, str] = {}
    for raw in props_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if not key.startswith("omod."):
            continue
        if key.endswith(_OMOD_ATTR_SUFFIXES):
            continue
        name = key[len("omod."):]
        repo = parse_repo(f"openmrs/openmrs-module-{name}")
        mod_map[name] = repo.full_name
        repos[repo.full_name] = repo
    return repos, mod_map


def _alt_repos(repo: Repo):
    """Candidate repos to try: the resolved one, then an '-app'-suffix toggle.

    OpenMRS esm repos drift between `openmrs-esm-x` and `openmrs-esm-x-app`, and
    the npm registry's repository.url often lags a rename. Toggling the suffix
    recovers those without fabricating arbitrary names.
    """
    yield repo
    if repo.name.endswith("-app"):
        yield Repo(repo.host, repo.owner, repo.name[:-len("-app")])
    else:
        yield Repo(repo.host, repo.owner, repo.name + "-app")


def _sbom_repo(repo: Repo, refresh: bool) -> tuple[str, Repo | None]:
    """Clone + Syft a wider-scope repo (with name fallback). Returns (status, repo_used)."""
    sbom_name = f"openmrs__{repo.slug}.cyclonedx.json"
    if provenance.raw_exists(SBOM_SOURCE, sbom_name) and not refresh:
        log.info("sbom skip (cached): %s", sbom_name)
        return "cached", repo
    last = "clone_failed"
    for cand in _alt_repos(repo):
        path = ensure_clone(cand, refresh=refresh)
        if path is None:
            continue
        try:
            sbom = _run_syft(path)
            n_syft = len(sbom.get("components", []) or [])
            added = _merge_manifest_deps(sbom, path)
            provenance.write_json(SBOM_SOURCE, f"openmrs__{cand.slug}.cyclonedx.json", sbom)
            note = "" if cand.name == repo.name else f" (resolved as {cand.name})"
            log.info("sbom ok %s%s (%d syft + %d manifest = %d)",
                     repo.full_name, note, n_syft, added, n_syft + added)
            return "ok", cand
        except Exception as exc:  # noqa: BLE001
            last = f"syft_failed: {exc}"
            log.error("syft failed %s: %s", cand.full_name, exc)
    log.warning("could not acquire %s (tried suffix fallback)", repo.full_name)
    return last, None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--part", choices=["frontend", "backend", "all"], default="all")
    args = p.parse_args()

    if not _ensure_image(SYFT_IMAGE):
        log.error("Syft image unavailable; cannot generate wider-scope SBOMs.")
        return 1

    distro_path = ensure_clone(parse_repo(DISTRO), refresh=args.refresh)
    if distro_path is None:
        log.error("could not clone the distro repo %s", DISTRO)
        return 1

    npm = _npm_client()
    frontend_repos: dict[str, Repo] = {}
    backend_repos: dict[str, Repo] = {}
    pkg_map: dict = {}
    mod_map: dict = {}
    unresolved: list = []
    statuses: dict[str, str] = {}
    sbom_repos: list[str] = []   # repos with a usable SBOM (post-fallback names)

    if args.part in ("frontend", "all"):
        text = _read_distro_file(distro_path, ASSEMBLE_PATH)
        provenance.write_text(SOURCE, "spa-assemble-config.json", text)
        frontend_repos, pkg_map, unresolved = _resolve_frontend(text, npm)
        log.info("frontend: %d shipped packages -> %d source repos (%d unresolved)",
                 len(pkg_map), len(frontend_repos), len(unresolved))
        for repo in frontend_repos.values():
            status, used = _sbom_repo(repo, args.refresh)
            statuses[repo.full_name] = status
            if used is not None:
                sbom_repos.append(used.full_name)

    if args.part in ("backend", "all"):
        text = _read_distro_file(distro_path, PROPS_PATH)
        provenance.write_text(SOURCE, "distro.properties", text)
        backend_repos, mod_map = _resolve_backend(text)
        log.info("backend: %d omod modules -> %d module repos", len(mod_map), len(backend_repos))
        for repo in backend_repos.values():
            status, used = _sbom_repo(repo, args.refresh)
            statuses[repo.full_name] = status
            if used is not None:
                sbom_repos.append(used.full_name)

    manifest = {
        "system_id": "openmrs",
        "scope": "o3_reference_application_as_shipped",
        "snapshot_date": config.snapshot_date(),
        "method": "syft-on-source-repo (deps.dev lacks resolved graphs for these "
                  "npm/maven artifacts); frontend repos resolved via npm "
                  "repository.url, backend via openmrs/openmrs-module-<name>",
        "frontend_packages": pkg_map,
        "frontend_repos": sorted(frontend_repos),
        "backend_modules": mod_map,
        "backend_repos": sorted(backend_repos),
        "sbom_repos": sorted(set(sbom_repos)),   # repos with a usable SBOM (authoritative for analysis)
        "unresolved": unresolved,
        "sbom_status": statuses,
    }
    ptr = provenance.write_json(SOURCE, "scope_manifest.json", manifest)
    ok = sum(1 for v in statuses.values() if v in ("ok", "cached"))
    log.info("wrote %s (repos=%d, sbom ok/cached=%d, failed=%d)",
             ptr, len(statuses), ok, len(statuses) - ok)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
