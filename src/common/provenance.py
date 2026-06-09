"""Dated raw-archive helpers + provenance pointers.

Every external response is archived verbatim under
``data/raw/<source>/<SNAPSHOT_DATE>/<name>`` so the dataset is fully traceable and
re-runs are idempotent (skip if the dated file already exists; pass ``refresh=True``
to force a re-fetch). Each dataset record stores a ``provenance`` pointer: the path
to its raw source, relative to the repository root.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import config


def raw_dir(source: str) -> Path:
    """data/raw/<source>/<SNAPSHOT_DATE>/  (created on demand)."""
    d = config.RAW_DIR / source / config.snapshot_date()
    d.mkdir(parents=True, exist_ok=True)
    return d


def raw_path(source: str, name: str) -> Path:
    return raw_dir(source) / name


def provenance_pointer(path: Path) -> str:
    """Path relative to the repo root, for the dataset's `provenance` field."""
    return str(Path(path).resolve().relative_to(config.ROOT))


def raw_exists(source: str, name: str) -> bool:
    return raw_path(source, name).exists()


def write_json(source: str, name: str, obj: Any) -> str:
    """Archive `obj` as pretty JSON; return its provenance pointer."""
    p = raw_path(source, name)
    p.write_text(json.dumps(obj, indent=2, sort_keys=False, default=str))
    return provenance_pointer(p)


def write_text(source: str, name: str, text: str) -> str:
    p = raw_path(source, name)
    p.write_text(text)
    return provenance_pointer(p)


def read_json(source: str, name: str) -> Any:
    return json.loads(raw_path(source, name).read_text())


def load_or_none(source: str, name: str) -> Any | None:
    """Return archived JSON if present, else None (for idempotent re-runs)."""
    p = raw_path(source, name)
    if p.exists():
        return json.loads(p.read_text())
    return None


# --- interim (transform stage) outputs --------------------------------------
def interim_path(name: str) -> Path:
    config.INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    return config.INTERIM_DIR / name


def write_interim_json(name: str, obj: Any) -> Path:
    p = interim_path(name)
    p.write_text(json.dumps(obj, indent=2, default=str))
    return p


def read_interim_json(name: str) -> Any:
    return json.loads(interim_path(name).read_text())
