"""Shallow git clones into clones/<slug>, shared by SBOM, LOC, and local Scorecard.

Clones are scratch (gitignored) and reused across modules to avoid cloning the
same repo multiple times. Shallow (depth 1) is enough for dependency manifests,
line counts, and Scorecard's file-based local checks.
"""
from __future__ import annotations

import shutil
import subprocess

from . import config
from .logging import get_logger
from .repos import Repo

log = get_logger("clone")


def clone_path(repo: Repo):
    return config.CLONES_DIR / repo.slug


def ensure_clone(repo: Repo, refresh: bool = False, depth: int = 1):
    """Clone (shallow) if absent; return the local path or None on failure."""
    dest = clone_path(repo)
    if dest.exists():
        if refresh:
            shutil.rmtree(dest)
        else:
            return dest
    config.CLONES_DIR.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", str(depth), "--quiet",
           repo.clone_url, str(dest)]
    log.info("cloning %s -> %s", repo.clone_url, dest)
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=900)
    except subprocess.CalledProcessError as exc:
        log.error("clone failed for %s: %s", repo.full_name, exc.stderr.strip()[:300])
        return None
    except subprocess.TimeoutExpired:
        log.error("clone timed out for %s", repo.full_name)
        return None
    return dest
