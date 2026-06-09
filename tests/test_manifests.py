"""Static manifest parsers (declared direct deps; exact-pin version capture)."""
from src.common import manifests as m


def test_pyproject_pep621_and_poetry():
    text = """
[project]
name = "x"
dependencies = ["flask>=2.0", "requests==2.31.0", "bcrypt"]
[project.optional-dependencies]
dev = ["pytest==8.0.0"]
[tool.poetry.dependencies]
python = "^3.11"
django = "4.2.0"
"""
    comps = {c["purl"]: c for c in m.parse_pyproject(text)}
    assert "pkg:pypi/requests@2.31.0" in comps          # exact pin kept
    assert "pkg:pypi/flask" in comps                      # range -> no version
    assert comps["pkg:pypi/flask"]["version"] is None
    assert "pkg:pypi/bcrypt" in comps
    assert "pkg:pypi/pytest@8.0.0" in comps               # optional-deps included
    assert "pkg:pypi/django@4.2.0" in comps              # poetry exact
    assert "pkg:pypi/python" not in comps                 # python itself skipped


def test_package_json_semver_exact_vs_range():
    text = '{"dependencies": {"lodash": "4.17.21", "express": "^4.18.0"}}'
    comps = {c["purl"]: c for c in m.parse_package_json(text)}
    assert "pkg:npm/lodash@4.17.21" in comps
    assert "pkg:npm/express" in comps
    assert comps["pkg:npm/express"]["version"] is None


def test_composer_skips_platform_reqs():
    text = '{"require": {"php": ">=8.1", "monolog/monolog": "2.9.1"}}'
    comps = {c["purl"]: c for c in m.parse_composer_json(text)}
    assert "pkg:composer/monolog/monolog@2.9.1" in comps
    assert all("php" != c["name"] for c in comps.values())  # platform req skipped


def test_gradle_coords_and_variable_versions():
    text = '''
    dependencies {
        implementation 'org.apache.commons:commons-lang3:3.12.0'
        api "com.google.guava:guava:${guavaVersion}"
    }
    '''
    comps = {c["purl"].split("@")[0]: c for c in m.parse_gradle(text)}
    assert comps["pkg:maven/org.apache.commons/commons-lang3"]["version"] == "3.12.0"
    assert comps["pkg:maven/com.google.guava/guava"]["version"] is None  # ${var}


def test_requirements_txt():
    comps = {c["purl"] for c in m.parse_requirements("flask==2.0.1\n# comment\n-r other.txt\nnumpy\n")}
    assert "pkg:pypi/flask@2.0.1" in comps
    assert "pkg:pypi/numpy" in comps
