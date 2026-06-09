"""Generate an SBOM per repo with Syft (Construct C) + capture LOC (Construct D).

Syft works on any forge (it scans a local clone), so it gives GNU Health an SBOM
even though GitHub's dependency-graph SBOM is unavailable there. Output is
CycloneDX-JSON (components + the dependency relationship graph used later to split
direct vs transitive). While the clone is on disk we also run cloc for LOC and
language mix (a Construct-D descriptor); cloc is best-effort and nulls on failure.

Both tools run via pinned Docker images (no Go/cloc toolchain on the host).
"""
from __future__ import annotations

import json
import subprocess

from ..common import config, manifests, provenance
from ..common.clone import ensure_clone
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.repos import Repo, parse_repo

log = get_logger("sbom_generate")
SOURCE = "sbom"
LOC_SOURCE = "cloc"

SYFT_IMAGE = "anchore/syft:latest"
CLOC_IMAGE = "aldanial/cloc:latest"


def _run_syft(clone_path) -> dict:
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{clone_path.resolve()}:/work:ro",
        SYFT_IMAGE, "dir:/work", "-o", "cyclonedx-json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"syft rc={proc.returncode}: {proc.stderr.strip()[:400]}")
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        raise RuntimeError("no JSON from syft")
    return json.loads(out[start:])


def _merge_manifest_deps(sbom: dict, clone_path) -> int:
    """Append declared direct deps (from manifests) not already in the Syft SBOM.

    Ensures pyproject-only / un-locked-Gradle projects have supply-chain data.
    Manifest components carry a location property so the direct/transitive heuristic
    marks them direct, and an ehr:source marker for provenance. Returns count added.
    """
    components = sbom.setdefault("components", [])
    existing = {c["purl"].split("@")[0] for c in components if c.get("purl")}
    added = 0
    for mc in manifests.scan_clone(clone_path):
        base = mc["purl"].split("@")[0]
        if base in existing:
            continue
        existing.add(base)
        comp = {
            "type": "library",
            "name": mc["name"],
            "purl": mc["purl"],
            "bom-ref": mc["purl"],
            "properties": [
                {"name": "syft:location:0:path", "value": mc["source_file"]},
                {"name": "ehr:source", "value": "manifest-parse"},
            ],
        }
        if mc["version"]:
            comp["version"] = mc["version"]
        components.append(comp)
        added += 1
    return added


def _run_cloc(clone_path) -> dict | None:
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{clone_path.resolve()}:/work:ro",
        CLOC_IMAGE, "--json", "--quiet", "/work",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("cloc run failed: %s", exc)
        return None
    if proc.returncode != 0:
        log.warning("cloc rc=%d: %s", proc.returncode, proc.stderr.strip()[:200])
        return None
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        return None
    try:
        return json.loads(out[start:])
    except json.JSONDecodeError:
        return None


def _ensure_image(image: str) -> bool:
    """Pull an image if not present locally. Returns True if available."""
    have = subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True, text=True)
    if have.returncode == 0:
        return True
    log.info("pulling %s ...", image)
    pull = subprocess.run(["docker", "pull", image], capture_output=True, text=True)
    if pull.returncode != 0:
        log.warning("could not pull %s: %s", image, pull.stderr.strip()[:200])
        return False
    return True


def main() -> int:
    args = parse_common_args(__doc__)
    cloc_ok = _ensure_image(CLOC_IMAGE)
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        for repo_str in system.core_repos:
            repo = parse_repo(repo_str)
            sbom_name = f"{system.id}__{repo.slug}.cyclonedx.json"
            loc_name = f"{system.id}__{repo.slug}.json"
            need_sbom = args.refresh or not provenance.raw_exists(SOURCE, sbom_name)
            need_loc = cloc_ok and (args.refresh or not provenance.raw_exists(LOC_SOURCE, loc_name))
            if not need_sbom and not need_loc:
                log.info("skip (cached): %s", sbom_name)
                continue

            path = ensure_clone(repo, refresh=args.refresh)
            if path is None:
                failures.append({"system_id": system.id, "repo": repo.host_full,
                                 "error": "clone failed"})
                continue

            if need_sbom:
                try:
                    sbom = _run_syft(path)
                    n_syft = len(sbom.get("components", []) or [])
                    added = _merge_manifest_deps(sbom, path)
                    ptr = provenance.write_json(SOURCE, sbom_name, sbom)
                    log.info("sbom ok %s -> %s (%d syft + %d manifest = %d components)",
                             repo.full_name, ptr, n_syft, added, n_syft + added)
                except Exception as exc:  # noqa: BLE001
                    log.error("FAILED syft %s: %s", repo.full_name, exc)
                    failures.append({"system_id": system.id, "repo": repo.host_full,
                                     "error": f"syft: {exc}"})

            if need_loc:
                loc = _run_cloc(path)
                if loc is not None:
                    loc["system_id"] = system.id
                    loc["repo"] = repo.host_full
                    loc["snapshot_date"] = config.snapshot_date()
                    provenance.write_json(LOC_SOURCE, loc_name, loc)
                    total = (loc.get("SUM", {}) or {}).get("code")
                    log.info("cloc ok %s (code lines=%s)", repo.full_name, total)

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
        log.warning("%d repo(s) failed; logged to _failures.json", len(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
