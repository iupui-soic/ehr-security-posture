"""Per-dimension comparisons for RQ1/RQ2/RQ3 (descriptive, grouped by system_type).

No inferential statistics (N=5). Each function returns a tidy DataFrame; main()
writes them to paper/figures/ as the data behind F1-F6 and the T2 posture matrix.
The shared-*vulnerable*-dependency table is the RQ3 centerpiece.
"""
from __future__ import annotations

import pandas as pd

from ..common.cli import parse_common_args
from ..common.logging import get_logger
from . import loaders

log = get_logger("comparisons")

SEV_ORDER = ["critical", "high", "medium", "low", "none"]
# Disclosure channels outside the CVE ecosystem; excluded from the CVE figures
# (F2/F2b/F3) and reported separately (T2 "Other disclosures" + T2b).
VENDOR_SOURCES = ["vendor_SA", "release_notes", "bug_tracker"]


def _cve_rows(v: pd.DataFrame) -> pd.DataFrame:
    """Disclosed-vuln rows from CVE-ecosystem channels only (drop vendor/curated)."""
    if v.empty or "source" not in v.columns:
        return v
    return v[~v["source"].isin(VENDOR_SOURCES)]


def _vendor_rows(v: pd.DataFrame) -> pd.DataFrame:
    if v.empty or "source" not in v.columns:
        return v.iloc[0:0]
    return v[v["source"].isin(VENDOR_SOURCES)]


# --- RQ1: practices --------------------------------------------------------- #
def scorecard_matrix(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    ps = t["practice_scores"]
    if ps.empty:
        return pd.DataFrame()
    assess = ps[ps["assessable"]]
    mat = (assess.pivot_table(index="check_name", columns="system_id",
                              values="score", aggfunc="mean")
           .reindex(columns=[s for s in loaders.SYSTEM_ORDER
                             if s in ps["system_id"].unique()]))
    return mat.round(2)


def not_assessable_mask(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    ps = t["practice_scores"]
    if ps.empty:
        return pd.DataFrame()
    # True where a (check, system) is entirely not-assessable
    g = ps.groupby(["check_name", "system_id"])["assessable"].any().unstack()
    return (~g.fillna(False)).reindex(
        columns=[s for s in loaders.SYSTEM_ORDER if s in g.columns])


# --- RQ2: disclosed-vuln landscape ----------------------------------------- #
def cve_severity_counts(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    v = _cve_rows(t["disclosed_vuln"])
    if v.empty:
        return pd.DataFrame()
    c = (v.assign(severity=v["severity"].fillna("none"))
         .pivot_table(index="system_id", columns="severity",
                      values="vuln_id", aggfunc="count", fill_value=0))
    c = c.reindex(columns=[s for s in SEV_ORDER if s in c.columns], fill_value=0)
    return loaders.order_systems(c.reset_index()).set_index("system_id")


def cve_by_year(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    v = _cve_rows(t["disclosed_vuln"])
    if v.empty:
        return pd.DataFrame()
    v = v.copy()
    v["year"] = pd.to_datetime(v["published_date"], errors="coerce").dt.year
    return (v.dropna(subset=["year"])
            .pivot_table(index="year", columns="system_id", values="vuln_id",
                         aggfunc="count", fill_value=0)
            .astype(int))


def owasp_distribution(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    v = _cve_rows(t["disclosed_vuln"])
    if v.empty:
        return pd.DataFrame()
    vv = v.assign(owasp_category=v["owasp_category"].fillna("Unmapped/Other"))
    return vv.pivot_table(index="owasp_category", columns="system_id",
                          values="vuln_id", aggfunc="count", fill_value=0)


# --- RQ3: supply chain (centerpiece) --------------------------------------- #
def dependency_vuln_counts(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    d = t["dependency"]
    if d.empty:
        return pd.DataFrame()
    d = d.copy()
    d["scope"] = d["is_direct"].map({True: "direct", False: "transitive"})
    rows = (d[d["max_severity"] != "none"]
            .pivot_table(index=["system_id", "scope"], columns="max_severity",
                         values="package", aggfunc="count", fill_value=0))
    keep = [s for s in SEV_ORDER if s in rows.columns and s != "none"]
    return rows.reindex(columns=keep, fill_value=0).reset_index()


def shared_vulnerable(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    s = t["shared_dependency"]
    if s.empty:
        return pd.DataFrame()
    sv = s[s["is_vulnerable"]].copy()
    sv["systems"] = sv["systems"].apply(
        lambda v: ", ".join(v) if isinstance(v, list) else v)
    cols = ["package", "ecosystem", "max_severity", "systems"]
    if "n_systems" in sv:
        cols.append("n_systems")
    return sv[cols].sort_values(
        ["max_severity"], key=lambda c: c.map({s: i for i, s in enumerate(SEV_ORDER)}))


def vendor_disclosures(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """T2b: disclosures made outside the CVE ecosystem (RQ2 channel-asymmetry)."""
    vr = _vendor_rows(t["disclosed_vuln"])
    if vr.empty:
        return pd.DataFrame()
    sysmap = (dict(zip(t["system"]["system_id"], t["system"]["display_name"]))
              if not t["system"].empty else {})
    out = vr.assign(System=vr["system_id"].map(lambda s: sysmap.get(s, s)))
    cols = ["System", "vuln_id", "source", "published_date", "severity",
            "owasp_category", "summary", "provenance"]
    out = out[[c for c in cols if c in out.columns]]
    return out.sort_values(["System", "published_date"], na_position="last")


# --- T2 posture matrix (explicitly NOT a single ranked score) -------------- #
def posture_matrix(t: dict[str, pd.DataFrame]) -> pd.DataFrame:
    sysd = t["system"]
    if sysd.empty:
        return pd.DataFrame()
    ps, v, d, sh = (t["practice_scores"], t["disclosed_vuln"],
                    t["dependency"], t["shared_dependency"])
    descr = t["descriptor"]
    sec_by = (dict(zip(descr["system_id"], descr["has_security_policy"]))
              if not descr.empty else {})
    rows = []
    vcve = _cve_rows(v)
    vven = _vendor_rows(v)
    for _, s in loaders.order_systems(sysd).iterrows():
        sid = s["system_id"]
        spm = ps[(ps["system_id"] == sid) & (ps["assessable"])] if not ps.empty else ps
        sv = vcve[vcve["system_id"] == sid] if not vcve.empty else vcve
        sother = vven[vven["system_id"] == sid] if not vven.empty else vven
        sd = d[d["system_id"] == sid] if not d.empty else d
        n_shared_vuln = 0
        if not sh.empty:
            n_shared_vuln = sum(1 for _, r in sh.iterrows()
                                if r["is_vulnerable"] and isinstance(r["systems"], list)
                                and sid in r["systems"])
        rows.append({
            "System": s["display_name"],
            "Type": s["system_type"].replace("clinical_", ""),
            "Scorecard mean (assessable)":
                round(spm["score"].dropna().mean(), 2)
                if not spm.empty and spm["score"].notna().any() else None,
            "Disclosed CVEs": int(len(sv)),
            "CVEs high+crit": int(sv["severity"].isin(["high", "critical"]).sum())
                              if not sv.empty else 0,
            "Other disclosures": int(len(sother)),
            "Deps": int(len(sd)),
            "Vulnerable deps": int((sd["max_severity"] != "none").sum())
                               if not sd.empty else 0,
            "Shared vulnerable deps": n_shared_vuln,
            "Security policy": bool(sec_by.get(sid, False)),
        })
    return pd.DataFrame(rows)


def main() -> int:
    parse_common_args(__doc__)
    t = loaders.load_all()

    def _ri(df):
        return df.reset_index() if df is not None and not df.empty else pd.DataFrame()

    artifacts = {
        "F1_scorecard_matrix": _ri(scorecard_matrix(t)),
        "F2_cve_severity": _ri(cve_severity_counts(t)),
        "F2b_cve_by_year": _ri(cve_by_year(t)),
        "F3_owasp_distribution": _ri(owasp_distribution(t)),
        "F5_dependency_vuln": dependency_vuln_counts(t),
        "F6_shared_vulnerable": shared_vulnerable(t),
        "T2_posture_matrix": posture_matrix(t),
        "T2b_vendor_disclosures": vendor_disclosures(t),
    }
    for name, df in artifacts.items():
        if df is not None and not df.empty:
            loaders.write_table(df, name)
            log.info("wrote %s (%d rows)", name, len(df))
        else:
            log.info("%s: empty (no data yet)", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
