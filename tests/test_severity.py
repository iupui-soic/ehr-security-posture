"""CVSS v3 base-score calculator + severity binning."""
from src.common import severity as sv


def test_cvss3_known_vectors():
    # critical (9.8), high (7.5), medium reflected-XSS (6.1)
    assert sv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert sv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert sv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


def test_cvss3_invalid_returns_none():
    assert sv.cvss3_base_score("not-a-vector") is None
    assert sv.cvss3_base_score("CVSS:3.1/AV:Z/AC:L") is None


def test_bin_score_cutoffs():
    assert sv.bin_score(0.0) == "none"
    assert sv.bin_score(3.9) == "low"
    assert sv.bin_score(4.0) == "medium"
    assert sv.bin_score(6.9) == "medium"
    assert sv.bin_score(7.0) == "high"
    assert sv.bin_score(9.0) == "critical"
    assert sv.bin_score(None) is None


def test_qualitative_and_max_bin():
    assert sv.qualitative_to_bin("MODERATE") == "medium"
    assert sv.qualitative_to_bin("CRITICAL") == "critical"
    assert sv.qualitative_to_bin(None) is None
    assert sv.max_bin(["low", "high", "medium"]) == "high"
    assert sv.max_bin([]) == "none"
    assert sv.max_bin([None, "low"]) == "low"


def test_severity_from_osv():
    rec = {"severity": [{"type": "CVSS_V3",
                         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    b, score, ver = sv.severity_from_osv(rec)
    assert b == "critical" and score == 9.8 and ver == "3.x"
    # fallback to GHSA qualitative
    rec2 = {"database_specific": {"severity": "HIGH"}}
    assert sv.severity_from_osv(rec2)[0] == "high"
