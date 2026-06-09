"""purl helpers, direct/transitive resolution, shared-dependency analysis (RQ3)."""
from src.transform import dependency_graph as dg


def test_purl_helpers():
    assert dg._purl_type("pkg:npm/lodash@4.17.20") == "npm"
    assert dg._purl_type("pkg:maven/com.x/y@1.0") == "maven"
    assert dg._purl_type("not-a-purl") is None
    assert dg._purl_base("pkg:npm/lodash@4.17.20") == "pkg:npm/lodash"
    assert dg._purl_base("pkg:maven/com.x/y@1.0?type=jar") == "pkg:maven/com.x/y"


def test_direct_map_from_graph():
    sbom = {
        "metadata": {"component": {"bom-ref": "root"}},
        "dependencies": [
            {"ref": "root", "dependsOn": ["a", "b"]},
            {"ref": "a", "dependsOn": ["c"]},
            {"ref": "b"},
            {"ref": "c"},
        ],
    }
    dm = dg._direct_map_from_graph(sbom)
    assert dm["a"] is True and dm["b"] is True
    assert dm["c"] is False
    # no graph -> None (caller falls back to manifest-location heuristic)
    assert dg._direct_map_from_graph({"dependencies": []}) is None


def _dep(purl, vuln_ids=(), sev="none", direct=True):
    return {
        "purl": purl, "purl_base": dg._purl_base(purl),
        "package": purl.split("/")[-1].split("@")[0], "ecosystem": dg._purl_type(purl),
        "version": purl.split("@")[-1], "is_direct": direct,
        "vuln_ids": list(vuln_ids), "max_severity": sev,
    }


def test_analyze_shared_finds_cross_system_spofs():
    per_system = {
        "sysA": {
            "pkg:npm/lodash@4.17.20": _dep("pkg:npm/lodash@4.17.20",
                                           vuln_ids=["GHSA-x"], sev="high"),
            "pkg:npm/left-pad@1.0.0": _dep("pkg:npm/left-pad@1.0.0"),
        },
        "sysB": {
            "pkg:npm/lodash@4.17.21": _dep("pkg:npm/lodash@4.17.21"),  # diff version
        },
        "sysC": {
            "pkg:npm/express@4.0.0": _dep("pkg:npm/express@4.0.0"),
        },
    }
    shared, graph = dg.analyze_shared(per_system)
    # lodash is shared by A and B (across versions); left-pad/express are not shared
    assert len(shared) == 1
    s = shared[0]
    assert s["package"] == "lodash"
    assert s["systems"] == ["sysA", "sysB"]
    assert s["n_systems"] == 2
    assert s["is_vulnerable"] is True          # vulnerable in sysA
    assert s["max_severity"] == "high"
    # bipartite graph has all 3 system nodes + 1 shared dep node
    kinds = [n.get("kind") for n in graph["nodes"]]
    assert kinds.count("system") == 3
    assert kinds.count("dependency") == 1


def test_analyze_shared_empty():
    shared, graph = dg.analyze_shared({"a": {}, "b": {}})
    assert shared == []
    assert [n for n in graph["nodes"] if n.get("kind") == "dependency"] == []
