"""CVSS scoring + severity binning, shared by Construct B and C.

NVD records already carry a numeric base score; OSV/GHSA records often carry only a
CVSS vector string (or a qualitative GHSA severity). This module turns any of those
into the NVD qualitative bins used throughout the dataset.
"""
from __future__ import annotations

import math

BINS = ["none", "low", "medium", "high", "critical"]
_ORDER = {b: i for i, b in enumerate(BINS)}


def bin_score(score: float | None) -> str | None:
    """Map a CVSS base score to NVD qualitative bins (v3 cutoffs)."""
    if score is None:
        return None
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def qualitative_to_bin(label: str | None) -> str | None:
    if not label:
        return None
    l = label.strip().lower()
    return {
        "none": "none", "low": "low", "moderate": "medium", "medium": "medium",
        "high": "high", "critical": "critical",
    }.get(l)


def max_bin(bins) -> str:
    """Highest severity bin in an iterable; 'none' if empty/all-unknown."""
    best = "none"
    for b in bins:
        if b in _ORDER and _ORDER[b] > _ORDER[best]:
            best = b
    return best


# --- CVSS v3.x base-score calculator (spec formula) -------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def parse_cvss_vector(vector: str) -> dict:
    out = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k] = v
    return out


def cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.0/3.1 base score from a vector string, else None."""
    try:
        m = parse_cvss_vector(vector)
        scope_changed = m.get("S") == "C"
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except (KeyError, AttributeError):
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    raw = (1.08 * (impact + exploit)) if scope_changed else (impact + exploit)
    return _roundup(min(raw, 10.0))


def severity_from_osv(record: dict) -> tuple[str | None, float | None, str | None]:
    """(bin, numeric_score, cvss_version) from an OSV/GHSA record, best-effort.

    Order: explicit CVSS vector (v4 then v3) -> GHSA qualitative severity.
    """
    for entry in record.get("severity", []) or []:
        typ = (entry.get("type") or "").upper()
        vec = entry.get("score") or ""
        if typ.startswith("CVSS_V3") and vec.startswith("CVSS:3"):
            sc = cvss3_base_score(vec)
            if sc is not None:
                return bin_score(sc), sc, "3.x"
        # v4 vectors: no closed-form calc here; record version, leave score null.
        if typ.startswith("CVSS_V4"):
            return None, None, "4.0"
    qual = (record.get("database_specific", {}) or {}).get("severity")
    b = qualitative_to_bin(qual)
    if b:
        return b, None, None
    return None, None, None
