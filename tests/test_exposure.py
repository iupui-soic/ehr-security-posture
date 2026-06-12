"""KEV/EPSS clinical-exposure join (RQ2 disclosed CVEs + RQ3 shared SPOFs)."""
from src.analyze import exposure as ex


def test_exposure_flags_kev_membership_and_passes_epss():
    kev = {"CVE-2022-22965"}
    epss = {"CVE-2022-22965": {"epss": 0.944, "percentile": 0.9999}}
    e = ex._exposure("CVE-2022-22965", kev, epss)
    assert e["in_kev"] is True
    assert e["epss"] == 0.944
    assert e["epss_percentile"] == 0.9999


def test_exposure_absent_cve_is_null_not_error():
    e = ex._exposure("CVE-2099-0001", set(), {})
    assert e["in_kev"] is False
    assert e["epss"] is None
    assert e["epss_percentile"] is None


def test_epss_high_threshold_is_half():
    # the ">50% modelled 30-day exploitation probability" cut reported in the paper
    assert ex.EPSS_HIGH == 0.5
