"""Descriptive tables T1 (system descriptors) + grouped summaries (Construct D).

Context only -- N=5, so this is descriptive, never inferential. Groups by
system_type so the application-vs-platform contrast is visible. Outputs T1 to
paper/figures/ as CSV + LaTeX.
"""
from __future__ import annotations

import pandas as pd

from ..common.cli import parse_common_args
from ..common.logging import get_logger
from . import loaders

log = get_logger("descriptive")


def table1(tables: dict[str, pd.DataFrame]) -> pd.DataFrame:
    system = tables["system"]
    descr = tables["descriptor"]
    if system.empty:
        return pd.DataFrame()
    df = system.merge(descr, on=["system_id", "snapshot_date"], how="left",
                      suffixes=("", "_d"))
    df = loaders.order_systems(df)
    out = pd.DataFrame({
        "System": df["display_name"],
        "Type": df["system_type"].map({"clinical_application": "application",
                                       "clinical_data_platform": "platform"}),
        "Forge": df["forge"],
        "Languages": df["primary_languages"].apply(
            lambda v: ", ".join(v) if isinstance(v, list) else ""),
        "Repos": df["repo_count"],
        "LOC": df["loc"],
        "Contributors": df["contributors"],
        "Releases": df["release_frequency"],
        "SecurityPolicy": df.apply(_policy_label, axis=1),
        "CVE match conf.": df["match_confidence_overall"],
    })
    return out


def _policy_label(row) -> str:
    """yes / yes (external docs) / no — distinguishes a repo SECURITY.md from a
    policy published only in external docs (e.g. GNU Health)."""
    if not row.get("has_security_policy"):
        return "no"
    return "yes (external)" if row.get("security_policy_source") == "external_docs" else "yes"


def main() -> int:
    parse_common_args(__doc__)
    tables = loaders.load_all()
    t1 = table1(tables)
    if t1.empty:
        log.warning("no system data; run the pipeline first")
        return 0
    loaders.write_table(
        t1, "T1_descriptors",
        caption="Five-system descriptors (context for RQ1/RQ3; N=5, descriptive only).",
        label="tab:descriptors")
    log.info("wrote T1_descriptors (%d systems)", len(t1))

    # grouped context summary (no inferential stats)
    grp = tables["descriptor"].merge(tables["system"][["system_id", "system_type"]],
                                     on="system_id", how="left")
    if not grp.empty:
        summary = grp.groupby("system_type").agg(
            n=("system_id", "count"),
            median_loc=("loc", "median"),
            with_security_policy=("has_security_policy", "sum"),
        ).reset_index()
        loaders.write_table(summary, "T1b_grouped_context",
                            caption="Descriptors grouped by system type.")
        log.info("grouped context:\n%s", summary.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
