"""Run OpenSSF Scorecard per repo (Construct A — development security practices).

GitHub repos: full remote Scorecard (all checks) via the official Docker image.
Codeberg repos (GNU Health): Scorecard's remote checks require a GitHub-hosted
repo, so they are NOT assessable. We still run Scorecard's *local* mode against a
shallow clone to recover the file-based checks it can compute offline (e.g.
Security-Policy, License, Pinned-Dependencies, Dangerous-Workflow); every check
Scorecard cannot compute is recorded as not_assessable and is **never imputed**.

Output: one Scorecard JSON per repo under data/raw/scorecard/<date>/.
"""
from __future__ import annotations

import json
import subprocess

from ..common import config, provenance
from ..common.clone import ensure_clone
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.repos import Repo, parse_repo

log = get_logger("scorecard_run")
SOURCE = "scorecard"

SCORECARD_IMAGE = "gcr.io/openssf/scorecard:stable"

# Canonical Scorecard v5 check set, so not_assessable cells are explicit.
ALL_CHECKS = [
    "Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices",
    "Code-Review", "Contributors", "Dangerous-Workflow", "Dependency-Update-Tool",
    "Fuzzing", "License", "Maintained", "Packaging", "Pinned-Dependencies",
    "SAST", "Security-Policy", "Signed-Releases", "Token-Permissions",
    "Vulnerabilities", "Webhooks",
]


# Checks that need extra token scopes (public_repo / admin:repo_hook). With a
# no-scope PAT Scorecard errors fatally on these, so the fallback excludes them.
SCOPE_GATED = ["Branch-Protection", "Webhooks"]
SAFE_SUBSET = [c for c in ALL_CHECKS if c not in SCOPE_GATED]


def _run_remote(repo: Repo, checks: list[str] | None = None) -> dict:
    token = config.github_token()
    if not token:
        raise RuntimeError("GITHUB_TOKEN required for remote Scorecard")
    cmd = [
        "docker", "run", "--rm", "-e", f"GITHUB_AUTH_TOKEN={token}",
        SCORECARD_IMAGE,
        f"--repo={repo.host_full}", "--format=json", "--show-details",
    ]
    if checks:
        cmd.append(f"--checks={','.join(checks)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    # Scorecard prints a banner before JSON; a failing check can set rc=1 while
    # still emitting results for the others -> use stdout JSON whenever present.
    out = proc.stdout
    start = out.find("{")
    if start >= 0:
        try:
            return json.loads(out[start:])
        except json.JSONDecodeError:
            pass
    raise RuntimeError(f"scorecard rc={proc.returncode}: {proc.stderr.strip()[:400]}")


def _run_local(repo: Repo, refresh: bool) -> dict | None:
    """Best-effort local-mode Scorecard for non-GitHub repos (file-based checks)."""
    path = ensure_clone(repo, refresh=refresh)
    if path is None:
        return None
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{path.resolve()}:/repo:ro",
        SCORECARD_IMAGE,
        "--local=/repo", "--format=json", "--show-details",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        log.warning("local scorecard rc=%d for %s: %s",
                    proc.returncode, repo.full_name, proc.stderr.strip()[:300])
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        log.warning("no JSON from local scorecard for %s", repo.full_name)
        return None
    try:
        return json.loads(out[start:])
    except json.JSONDecodeError:
        return None


CODEBERG_REASON = ("Scorecard remote check requires a GitHub-hosted repo; "
                   "GNU Health is on Codeberg (Gitea). Not assessable.")
SCOPE_REASON = ("Scorecard could not run this check with the provided GITHUB_TOKEN "
                "scopes (needs public_repo / admin:repo_hook). Not assessable.")


def _mark_not_assessable(repo: Repo, partial: dict | None, reason: str,
                         mode: str) -> dict:
    """Wrap a partial result, marking checks Scorecard didn't return not_assessable."""
    got = {}
    for chk in (partial or {}).get("checks", []) or []:
        got[chk.get("name")] = chk
    checks_out = []
    for name in ALL_CHECKS:
        if name in got:
            c = got[name]
            checks_out.append({
                "name": name,
                "score": c.get("score"),
                "reason": c.get("reason"),
                "assessable": True,
                "details": c.get("details"),
            })
        else:
            checks_out.append({
                "name": name, "score": None, "reason": reason, "assessable": False,
            })
    return {
        "repo": {"name": repo.host_full},
        "mode": mode,
        "checks": checks_out,
        "raw_partial": partial,
    }


def main() -> int:
    args = parse_common_args(__doc__)
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        for repo_str in system.core_repos:
            repo = parse_repo(repo_str)
            name = f"{system.id}__{repo.slug}.json"
            if provenance.raw_exists(SOURCE, name) and not args.refresh:
                log.info("skip (cached): %s", name)
                continue
            try:
                if repo.is_github:
                    try:
                        result = _run_remote(repo)
                        result["_assessable_mode"] = "remote"
                    except RuntimeError as exc:
                        log.warning("full Scorecard failed for %s (%s); retrying "
                                    "without scope-gated checks", repo.full_name,
                                    str(exc)[:120])
                        sub = _run_remote(repo, checks=SAFE_SUBSET)
                        result = _mark_not_assessable(repo, sub, SCOPE_REASON,
                                                      "remote-subset")
                        result["_assessable_mode"] = "remote-subset"
                else:
                    local = _run_local(repo, refresh=args.refresh)
                    result = _mark_not_assessable(repo, local, CODEBERG_REASON,
                                                  "local+not_assessable")
                    result["_assessable_mode"] = "local+not_assessable"
                result["system_id"] = system.id
                result["scorecard_version"] = config.load_snapshot().tool_versions.get(
                    "scorecard")
                result["snapshot_date"] = config.snapshot_date()
                ptr = provenance.write_json(SOURCE, name, result)
                n_checks = len(result.get("checks", []) or [])
                log.info("ok %s -> %s (%d checks)", repo.full_name, ptr, n_checks)
            except Exception as exc:  # noqa: BLE001 — log & continue, never abort batch
                log.error("FAILED scorecard %s: %s", repo.full_name, exc)
                failures.append({"system_id": system.id,
                                 "repo": repo.host_full, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
        log.warning("%d repo(s) failed; logged to _failures.json", len(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
