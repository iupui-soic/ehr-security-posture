"""CWE->OWASP classification + NVD field extraction (Construct B)."""
from src.transform import cve_classify as cc


def test_owasp_mapping_basic():
    assert cc.classify_owasp(["CWE-89"]).startswith("A03")    # SQLi -> Injection
    assert cc.classify_owasp(["CWE-79"]).startswith("A03")    # XSS  -> Injection
    assert cc.classify_owasp(["CWE-918"]).startswith("A10")   # SSRF
    assert cc.classify_owasp(["CWE-352"]).startswith("A01")   # CSRF -> Broken Access (2021)
    assert cc.classify_owasp(["CWE-502"]).startswith("A08")   # deserialization
    assert cc.classify_owasp(["CWE-9999999"]) is None         # unmapped


def test_owasp_priority_picks_highest():
    # A03 outranks A10 (string order A03 < A10)
    assert cc.classify_owasp(["CWE-918", "CWE-89"]).startswith("A03")
    # unmapped + mapped -> the mapped one
    assert cc.classify_owasp(["CWE-9999999", "CWE-918"]).startswith("A10")


def test_extract_cwes_dedupes_and_filters():
    cve = {"weaknesses": [
        {"description": [{"value": "CWE-79"}, {"value": "CWE-79"}]},
        {"description": [{"value": "NVD-CWE-noinfo"}]},
        {"description": [{"value": "CWE-89"}]},
    ]}
    assert cc._extract_cwes(cve) == ["CWE-79", "CWE-89"]


def test_extract_cvss_prefers_v31_over_v2():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
    }
    ver, score, sev = cc._extract_cvss(metrics)
    assert ver == "3.1" and score == 9.8 and sev == "critical"


def test_extract_cvss_v2_fallback_and_empty():
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}
    ver, score, sev = cc._extract_cvss(metrics)
    assert ver == "2.0" and score == 5.0 and sev == "medium"
    assert cc._extract_cvss({}) == (None, None, None)
