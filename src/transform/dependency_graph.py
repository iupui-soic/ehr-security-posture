"""Dependency tables + the cross-system shared-dependency graph (RQ3 centerpiece).

For each system we parse its Syft CycloneDX SBOM(s) into a dependency table
(package, ecosystem, version, direct-vs-transitive, vuln ids, max severity), then
build the union across all five systems and enumerate:

  * **shared dependencies** -- a package (purl without version) used by >1 system,
  * **shared *vulnerable* dependencies** -- the cross-system single points of
    failure that are the strongest argument for studying several EHRs together.

Outputs (data/interim/): dependencies.json, shared_dependencies.json,
dependency_graph.json (a system<->dependency bipartite graph for figure F6).

Direct-vs-transitive comes from the CycloneDX dependency graph (root.dependsOn);
when that graph is absent it falls back to the manifest-vs-lockfile location of the
component.
"""
from __future__ import annotations

import networkx as nx

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.logging import get_logger
from ..common.repos import parse_repo
from ..common.severity import max_bin

log = get_logger("dependency_graph")

# Component locations that indicate a *declared* (direct) dependency.
MANIFEST_FILES = (
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "composer.json", "go.mod", "Gemfile", "Cargo.toml",
)

# Components whose every recorded location is under a vendored tooling / docs path
# are NOT part of the running application and must not count toward supply-chain
# risk. Surfaced by reachability analysis: OpenEMR's apparent Maven deps came
# entirely from a bundled SchemaSpy schema-diagram jar under Documentation/, never
# invoked by the PHP app. Patterns are matched against Syft component locations.
VENDORED_LOCATION_PATTERNS = ("/Documentation/EHI_Export/schemaspy/",)


def _purl_type(purl: str) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].split("@", 1)[0]


def _purl_base(purl: str) -> str:
    """purl without version/qualifiers -> stable cross-version, cross-system key."""
    base = purl.split("@", 1)[0]
    return base.split("?", 1)[0]


def _component_locations(comp: dict) -> list[str]:
    locs = []
    for p in comp.get("properties", []) or []:
        name = p.get("name", "")
        if "location" in name and "path" in name:
            locs.append(p.get("value", ""))
    return locs


def _is_vendored(comp: dict) -> bool:
    """True iff every recorded location of the component is under a vendored path."""
    locs = _component_locations(comp)
    return bool(locs) and all(
        any(pat in loc for pat in VENDORED_LOCATION_PATTERNS) for loc in locs)


def _direct_map_from_graph(sbom: dict) -> dict[str, bool] | None:
    deps = sbom.get("dependencies", []) or []
    if not deps:
        return None
    depends = {d["ref"]: d.get("dependsOn", []) or [] for d in deps if "ref" in d}
    root = (sbom.get("metadata", {}) or {}).get("component", {}).get("bom-ref")
    if not root or root not in depends or not depends[root]:
        return None
    direct = set(depends[root])
    out: dict[str, bool] = {}
    for d in deps:
        out[d["ref"]] = d["ref"] in direct
    return out


def _system_dependencies(system) -> dict[str, dict]:
    """purl(with version) -> dependency record, unioned over the system's repos."""
    out: dict[str, dict] = {}
    n_vendored = 0
    depvulns = provenance.load_or_none("depvulns", f"{system.id}.json") or {}
    vuln_map = depvulns.get("vuln_map", {})
    vuln_details = depvulns.get("vuln_details", {})

    for repo_str in system.core_repos:
        repo = parse_repo(repo_str)
        sbom = provenance.load_or_none("sbom", f"{system.id}__{repo.slug}.cyclonedx.json")
        if not sbom:
            continue
        prov = provenance.provenance_pointer(
            provenance.raw_path("sbom", f"{system.id}__{repo.slug}.cyclonedx.json"))
        graph_direct = _direct_map_from_graph(sbom)

        for comp in sbom.get("components", []) or []:
            purl = comp.get("purl")
            if not purl:
                continue
            if _is_vendored(comp):  # bundled tooling/docs, not the running app
                n_vendored += 1
                continue
            ref = comp.get("bom-ref", purl)
            if graph_direct is not None:
                is_direct = graph_direct.get(ref, False)
            else:
                locs = _component_locations(comp)
                is_direct = any(loc.rsplit("/", 1)[-1] in MANIFEST_FILES for loc in locs)

            vinfo = vuln_map.get(purl)
            vuln_ids = vinfo["vuln_ids"] if vinfo else []
            sev = max_bin(vuln_details.get(v, {}).get("severity") for v in vuln_ids)

            rec = {
                "system_id": system.id,
                "package": comp.get("name"),
                "ecosystem": _purl_type(purl),
                "version": comp.get("version"),
                "purl": purl,
                "purl_base": _purl_base(purl),
                "is_direct": is_direct,
                "vuln_ids": vuln_ids,
                "max_severity": sev if vuln_ids else "none",
                "snapshot_date": config.snapshot_date(),
                "provenance": prov,
            }
            # union across repos: keep the vulnerable / direct-est instance
            if purl in out:
                prev = out[purl]
                rec["is_direct"] = prev["is_direct"] or is_direct
            out[purl] = rec
    if n_vendored:
        log.info("%s: excluded %d vendored components (bundled tooling/docs)",
                 system.id, n_vendored)
    return out


def analyze_shared(per_system: dict[str, dict[str, dict]],
                   system_meta: dict[str, dict] | None = None,
                   reachable_fn=None):
    """Pure: from {sid: {purl: dep_rec}} compute (shared_list, bipartite_graph_data).

    A dependency is "shared" when its purl_base is used by >1 system. Severity of a
    shared node is the max over the vulnerable instances across systems.

    ``reachable_fn(system_id, package, ecosystem, purl_base) -> bool`` (optional)
    annotates each vulnerable shared node with the subset of systems that genuinely
    reach it (``reachable_systems``); without it, all using systems are recorded.
    """
    system_meta = system_meta or {}
    base_to_systems: dict[str, set[str]] = {}
    base_meta: dict[str, dict] = {}
    base_severities: dict[str, list[str]] = {}
    for sid, deps in per_system.items():
        for d in deps.values():
            b = d["purl_base"]
            base_to_systems.setdefault(b, set()).add(sid)
            base_meta.setdefault(b, {"package": d["package"], "ecosystem": d["ecosystem"]})
            if d["vuln_ids"]:
                base_severities.setdefault(b, []).append(d["max_severity"])

    # Reachable subset per shared base (computed for vulnerable nodes when a
    # reachable_fn is supplied; otherwise every using system is "reachable").
    reach_map: dict[str, list[str]] = {}
    for b, sids in base_to_systems.items():
        if len(sids) < 2:
            continue
        sids_sorted = sorted(sids)
        if reachable_fn is not None and base_severities.get(b):
            reach_map[b] = [s for s in sids_sorted if reachable_fn(
                s, base_meta[b]["package"], base_meta[b]["ecosystem"], b)]
        else:
            reach_map[b] = sids_sorted

    shared: list[dict] = []
    for b, sids in base_to_systems.items():
        if len(sids) < 2:
            continue
        sevs = base_severities.get(b, [])
        shared.append({
            "package": base_meta[b]["package"],
            "ecosystem": base_meta[b]["ecosystem"],
            "purl_base": b,
            "systems": sorted(sids),
            "n_systems": len(sids),
            "is_vulnerable": bool(sevs),
            "max_severity": max_bin(sevs) if sevs else "none",
            "reachable_systems": reach_map[b],
            "n_reachable": len(reach_map[b]),
            "snapshot_date": config.snapshot_date(),
        })
    shared.sort(key=lambda r: (-r["n_systems"], not r["is_vulnerable"], r["package"]))

    g = nx.Graph()
    for sid in per_system:
        meta = system_meta.get(sid, {})
        g.add_node(f"sys:{sid}", kind="system",
                   system_type=meta.get("system_type", ""),
                   label=meta.get("display_name", sid))
    for b, sids in base_to_systems.items():
        if len(sids) < 2:
            continue  # F6 shows only shared deps for readability
        sevs = base_severities.get(b, [])
        g.add_node(f"dep:{b}", kind="dependency", label=base_meta[b]["package"],
                   ecosystem=base_meta[b]["ecosystem"],
                   vulnerable=bool(sevs), max_severity=max_bin(sevs) if sevs else "none",
                   n_systems=len(sids), reachable_systems=reach_map[b])
        for sid in sids:
            g.add_edge(f"sys:{sid}", f"dep:{b}")
    graph_data = nx.node_link_data(g, edges="links")
    return shared, graph_data


def build():
    systems = config.load_systems()
    all_deps: list[dict] = []
    per_system: dict[str, dict[str, dict]] = {}
    for system in systems:
        deps = _system_dependencies(system)
        per_system[system.id] = deps
        all_deps.extend(deps.values())
        n_vuln = sum(1 for d in deps.values() if d["vuln_ids"])
        log.info("%s: %d deps (%d vulnerable, %d direct)",
                 system.id, len(deps), n_vuln,
                 sum(1 for d in deps.values() if d["is_direct"]))

    system_meta = {s.id: {"system_type": s.system_type, "display_name": s.display_name}
                   for s in systems}

    from . import reachability  # local import: only build() needs the clones

    def _reach(sid, package, ecosystem, base):
        recs = per_system.get(sid, {})
        if any(d["is_direct"] for d in recs.values() if d["purl_base"] == base):
            return True  # directly declared (covers JDBC drivers reached via JDBC)
        return reachability.source_referenced(sid, package, ecosystem)

    shared, graph_data = analyze_shared(per_system, system_meta, reachable_fn=_reach)

    provenance.write_interim_json("dependencies.json", all_deps)
    provenance.write_interim_json("shared_dependencies.json", shared)
    provenance.write_interim_json("dependency_graph.json", graph_data)

    n_shared_vuln = sum(1 for s in shared if s["is_vulnerable"])
    n_reach_spof = sum(1 for s in shared if s["is_vulnerable"] and s["n_reachable"] >= 2)
    log.info("wrote %d dependency rows; %d shared deps (%d shared & vulnerable; "
             "%d reachable cross-system SPOFs)",
             len(all_deps), len(shared), n_shared_vuln, n_reach_spof)
    return all_deps, shared


def main() -> int:
    parse_common_args(__doc__)
    build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
