"""Dataset schema validation + sample/config sanity."""
import json

from src.common import config
from src.common.repos import parse_repo
from src.transform import build_dataset as bd


def test_schema_file_well_formed():
    schema = json.loads(config.SCHEMA_JSON.read_text())
    entities = schema["entities"]
    for required in ("system", "practice_scores", "disclosed_vuln", "dependency",
                     "shared_dependency", "descriptor"):
        assert required in entities
        assert entities[required]["fields"]


def test_validate_against_schema_detects_missing_fields():
    schema = json.loads(config.SCHEMA_JSON.read_text())
    # a valid minimal system row carries every declared field
    sys_fields = {k: None for k in schema["entities"]["system"]["fields"]}
    ok = bd.validate_against_schema({e: [] for e in schema["entities"]} |
                                    {"system": [sys_fields]})
    assert ok == []
    # dropping a field is caught
    broken = dict(sys_fields)
    broken.pop("system_id")
    errs = bd.validate_against_schema({e: [] for e in schema["entities"]} |
                                      {"system": [broken]})
    assert any("system" in e and "system_id" in e for e in errs)


def test_builders_conform_to_schema_with_no_raw_data():
    # With no acquired data the entity tables are empty, which is allowed
    # (sparsity is a finding); the builders must still run and validate.
    tables = {
        "system": bd.build_system(),
        "practice_scores": bd.build_practice_scores(),
        "disclosed_vuln": bd.build_disclosed_vuln(),
        "dependency": bd.build_dependency(),
        "shared_dependency": bd.build_shared_dependency(),
        "descriptor": bd.build_descriptor(),
    }
    # system + descriptor are derived from config alone -> always populated
    assert len(tables["system"]) == 5
    assert len(tables["descriptor"]) == 5
    assert bd.validate_against_schema(tables) == []


def test_sample_is_five_systems_with_types():
    systems = config.load_systems()
    assert len(systems) == 5
    types = {s.system_type for s in systems}
    assert types == {"clinical_application", "clinical_data_platform"}


def test_repo_parsing_github_and_codeberg():
    gh = parse_repo("openmrs/openmrs-core")
    assert gh.host == "github.com" and gh.is_github
    cb = parse_repo("codeberg.org/gnuhealth/his")
    assert cb.host == "codeberg.org" and cb.is_codeberg
    assert cb.clone_url == "https://codeberg.org/gnuhealth/his.git"
