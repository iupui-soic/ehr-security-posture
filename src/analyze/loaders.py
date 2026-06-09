"""Load the processed dataset tables as DataFrames for analysis/figures.

JSON-encoded array/object columns (see build_dataset.JSON_COLS) are decoded back
to Python objects here so analysis code sees lists/dicts, not strings.
"""
from __future__ import annotations

import json

import pandas as pd

from ..common import config

JSON_COLS = {"primary_languages", "core_repos", "cpe_hints", "cwe", "vuln_ids",
             "systems", "language_mix"}

# Stable display order: applications first, then platforms.
SYSTEM_ORDER = ["openmrs", "openemr", "gnuhealth", "ehrbase", "medplum"]


def _decode(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if col in JSON_COLS:
            df[col] = df[col].apply(
                lambda v: json.loads(v) if isinstance(v, str) and v else v)
    return df


def load(name: str) -> pd.DataFrame:
    path = config.PROCESSED_DIR / f"{name}.parquet"
    if not path.exists():
        return pd.DataFrame()
    return _decode(pd.read_parquet(path))


def load_all() -> dict[str, pd.DataFrame]:
    return {n: load(n) for n in
            ("system", "practice_scores", "disclosed_vuln", "dependency",
             "shared_dependency", "descriptor", "ehr_security_dataset")}


def order_systems(df: pd.DataFrame, col: str = "system_id") -> pd.DataFrame:
    if df.empty or col not in df:
        return df
    cat = pd.Categorical(df[col], categories=SYSTEM_ORDER, ordered=True)
    return df.assign(**{col: cat}).sort_values(col)


def write_table(df: pd.DataFrame, basename: str, caption: str = "", label: str = "") -> None:
    """Write a table as CSV + LaTeX into paper/figures/ (deterministic)."""
    config.PAPER_FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(config.PAPER_FIGURES_DIR / f"{basename}.csv", index=False)
    try:
        tex = df.to_latex(index=False, escape=True, na_rep="--",
                          caption=caption or basename, label=label or f"tab:{basename}")
        (config.PAPER_FIGURES_DIR / f"{basename}.tex").write_text(tex)
    except Exception:  # noqa: BLE001 — LaTeX export is best-effort
        pass
