"""Central configuration: paths, snapshot anchor, system sample, credentials.

Everything downstream reads the study's parameters from here so there is a single
authoritative source. `config/systems.yaml` defines the sample; `config/snapshot.yaml`
defines the reproducibility anchor (date, endpoints, tool versions). Credentials are
read from the environment (optionally via a gitignored `.env`), never committed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

# --- Repository layout -------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"
SCHEMA_DIR = ROOT / "schema"
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
PAPER_FIGURES_DIR = ROOT / "paper" / "figures"
CLONES_DIR = ROOT / "clones"          # scratch repo clones for SBOM / LOC
SCRIPTS_DIR = ROOT / "scripts"

SYSTEMS_YAML = CONFIG_DIR / "systems.yaml"
SNAPSHOT_YAML = CONFIG_DIR / "snapshot.yaml"
SCHEMA_JSON = SCHEMA_DIR / "dataset_schema.json"

# Load .env once, on import, so `python -m src.*` picks up tokens transparently.
load_dotenv(ROOT / ".env")


# --- Snapshot anchor ---------------------------------------------------------
@dataclass(frozen=True)
class Snapshot:
    """The reproducibility anchor from config/snapshot.yaml."""

    date: str
    tool_versions: dict
    endpoints: dict
    http: dict
    required_env: list[str]
    optional_env: list[str]
    construct_e_enabled: bool
    raw: dict = field(repr=False, default_factory=dict)


@lru_cache(maxsize=1)
def load_snapshot() -> Snapshot:
    data = yaml.safe_load(SNAPSHOT_YAML.read_text())
    return Snapshot(
        date=str(data.get("snapshot_date", "TBD")),
        tool_versions=data.get("tool_versions", {}) or {},
        endpoints=data.get("endpoints", {}) or {},
        http=data.get("http", {}) or {},
        required_env=list(data.get("required_env", []) or []),
        optional_env=list(data.get("optional_env", []) or []),
        construct_e_enabled=bool(data.get("construct_e_enabled", False)),
        raw=data,
    )


def snapshot_date() -> str:
    return load_snapshot().date


# --- System sample -----------------------------------------------------------
@dataclass(frozen=True)
class System:
    """One studied system, projected from config/systems.yaml."""

    id: str
    display_name: str
    forge: str                  # "github" | "codeberg"
    org_url: str
    primary_languages: list[str]
    system_type: str            # "clinical_application" | "clinical_data_platform"
    license: str
    repo_scope_rule: str
    core_repos: list[str]
    cpe_hints: list[str]
    ghsa_search_terms: list[str]
    raw: dict = field(repr=False, default_factory=dict)

    @property
    def is_github(self) -> bool:
        return self.forge == "github"

    @property
    def is_codeberg(self) -> bool:
        return self.forge == "codeberg"


@lru_cache(maxsize=1)
def _systems_doc() -> dict:
    return yaml.safe_load(SYSTEMS_YAML.read_text())


@lru_cache(maxsize=1)
def load_systems() -> list[System]:
    """Return the included systems, in declaration order."""
    out: list[System] = []
    for s in _systems_doc().get("systems", []):
        if not s.get("included", True):
            continue
        ident = s.get("identifiers", {}) or {}
        out.append(
            System(
                id=s["id"],
                display_name=s.get("display_name", s["id"]),
                forge=s.get("forge", "github"),
                org_url=s.get("org_url", ""),
                primary_languages=list(s.get("primary_languages", []) or []),
                system_type=s.get("system_type", "clinical_application"),
                license=s.get("license", ""),
                repo_scope_rule=(s.get("repo_scope_rule") or "").strip(),
                core_repos=list(s.get("core_repos", []) or []),
                cpe_hints=list(ident.get("cpe_hints", []) or []),
                ghsa_search_terms=list(ident.get("ghsa_search_terms", []) or []),
                raw=s,
            )
        )
    return out


def get_system(system_id: str) -> System:
    for s in load_systems():
        if s.id == system_id:
            return s
    raise KeyError(f"unknown system_id: {system_id!r}")


def excluded_systems() -> list[dict]:
    return list(_systems_doc().get("excluded", []) or [])


# --- Credentials -------------------------------------------------------------
def github_token() -> str | None:
    return os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def nvd_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY")


def codeberg_token() -> str | None:
    return os.environ.get("CODEBERG_TOKEN")


def endpoint(name: str) -> str:
    eps = load_snapshot().endpoints
    if name not in eps:
        raise KeyError(f"no endpoint named {name!r} in snapshot.yaml")
    return eps[name]
