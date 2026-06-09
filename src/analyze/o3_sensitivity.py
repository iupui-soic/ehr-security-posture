"""RQ3 supply-chain sensitivity check: OpenMRS core scope vs O3-as-shipped.

The OpenMRS dependency surface is scope-sensitive (multi-repo project). This
module recomputes the RQ3 dependency-risk picture with OpenMRS widened from its
4 core repos to the full O3 reference-application as shipped (core repos + the
frontend microfrontend source repos acquired by acquire/o3_wide.py), then reports
the delta. The other four systems stay at core scope. Outputs:

  * paper/figures/T3_o3_scope_sensitivity.csv  -- core-vs-wide summary
  * paper/figures/F6b_shared_vulnerable_o3wide.csv -- shared-vulnerable nodes at
    wide scope, flagging those that surface only because of the wider scope
  * data/interim/o3wide_{dependencies,shared,graph}.json

Reuses the same OSV scoring (acquire/deps_dev) and the pure shared-dependency
analysis (transform/dependency_graph.analyze_shared), so numbers are consistent
with the core pipeline. Run after the core pipeline + acquire/o3_wide.py.
"""
from __future__ import annotations

import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402

from ..acquire.deps_dev import _osv_batch, _vuln_detail
from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import osv_client
from ..common.logging import get_logger
from ..common.repos import parse_repo
from ..common.severity import max_bin
from ..transform.dependency_graph import (
    MANIFEST_FILES, _component_locations, _direct_map_from_graph,
    _purl_base, _purl_type, analyze_shared,
)

log = get_logger("o3_sensitivity")
SEV_ORDER = ["critical", "high", "medium", "low"]


def _wide_repo_slugs() -> list[str]:
    """Core OpenMRS repos + the frontend repos acquired by o3_wide (deduped)."""
    manifest = provenance.load_or_none("o3wide", "scope_manifest.json")
    if not manifest:
        raise SystemExit("missing data/raw/o3wide/<date>/scope_manifest.json; "
                         "run `python -m src.acquire.o3_wide` first.")
    openmrs = config.get_system("openmrs")
    repos = list(openmrs.core_repos) + list(manifest.get("sbom_repos", []))
    seen, out = set(), []
    for r in repos:
        slug = parse_repo(r).slug
        if slug not in seen:
            seen.add(slug)
            out.append(r)
    return out


def _components_over_repos(repo_strs: list[str]) -> dict[str, dict]:
    """Unique packages (keyed by purl) across the given repos' SBOMs."""
    comps: dict[str, dict] = {}
    for repo_str in repo_strs:
        repo = parse_repo(repo_str)
        sbom = provenance.load_or_none("sbom", f"openmrs__{repo.slug}.cyclonedx.json")
        if not sbom:
            log.warning("no SBOM for %s; skipping", repo.full_name)
            continue
        for c in sbom.get("components", []) or []:
            purl = c.get("purl")
            if not purl or purl in comps:
                continue
            comps[purl] = {"purl": purl, "name": c.get("name"),
                           "version": c.get("version"),
                           "ecosystem": None, "purl_type": _purl_type(purl)}
    return comps


def _vuln_lookup(comps: dict[str, dict]) -> tuple[dict, dict]:
    """OSV-score the components. Returns (vuln_map[purl], vuln_details[id])."""
    osv = osv_client()
    hits = _osv_batch(osv, list(comps), comps) if comps else {}
    details: dict[str, dict] = {}
    for ids in hits.values():
        for vid in ids:
            if vid not in details:
                d = _vuln_detail(osv, vid)
                if d:
                    details[vid] = d
    vuln_map = {purl: {**comps[purl], "vuln_ids": ids} for purl, ids in hits.items()}
    return vuln_map, details


def _deps_from_repos(repo_strs: list[str], vuln_map: dict, vuln_details: dict) -> dict[str, dict]:
    """Build {purl: dependency_record} over the repos (mirrors dependency_graph)."""
    out: dict[str, dict] = {}
    for repo_str in repo_strs:
        repo = parse_repo(repo_str)
        sbom = provenance.load_or_none("sbom", f"openmrs__{repo.slug}.cyclonedx.json")
        if not sbom:
            continue
        graph_direct = _direct_map_from_graph(sbom)
        for comp in sbom.get("components", []) or []:
            purl = comp.get("purl")
            if not purl:
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
                "system_id": "openmrs",
                "package": comp.get("name"),
                "ecosystem": _purl_type(purl),
                "version": comp.get("version"),
                "purl": purl,
                "purl_base": _purl_base(purl),
                "is_direct": is_direct,
                "vuln_ids": vuln_ids,
                "max_severity": sev if vuln_ids else "none",
            }
            if purl in out:
                rec["is_direct"] = out[purl]["is_direct"] or is_direct
            out[purl] = rec
    return out


def _core_per_system() -> dict[str, dict[str, dict]]:
    """Reconstruct {sid: {purl: rec}} for all five systems from the core interim."""
    rows = provenance.read_interim_json("dependencies.json")
    per: dict[str, dict[str, dict]] = {}
    for r in rows:
        per.setdefault(r["system_id"], {})[r["purl"]] = r
    return per


def _summarize(deps: dict[str, dict]) -> dict:
    vuln = [d for d in deps.values() if d["vuln_ids"]]
    sev = {s: sum(1 for d in vuln if d["max_severity"] == s) for s in SEV_ORDER}
    return {
        "total_deps": len(deps),
        "direct": sum(1 for d in deps.values() if d["is_direct"]),
        "transitive": sum(1 for d in deps.values() if not d["is_direct"]),
        "vulnerable": len(vuln),
        **{f"vuln_{s}": sev[s] for s in SEV_ORDER},
    }


def _shared_vuln_touching(shared: list[dict], sid: str) -> dict[str, dict]:
    return {s["purl_base"]: s for s in shared if s["is_vulnerable"] and sid in s["systems"]}


def _write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _render_graph(graph_data: dict, path, new_bases: set[str]):
    """F6b: shared-dependency graph at O3-as-shipped scope (mirrors F6).

    Nodes only reachable because of the wider OpenMRS scope are outlined in blue.
    """
    full = nx.node_link_graph(graph_data, edges="links")
    # Prune to shared *vulnerable* nodes (the single-points-of-failure the figure is
    # about) + the systems. Keeps the layout small and avoids the scipy-backed
    # sparse solver spring_layout needs above ~500 nodes.
    sys_nodes = [n for n, d in full.nodes(data=True) if d.get("kind") == "system"]
    vuln = [n for n, d in full.nodes(data=True)
            if d.get("kind") == "dependency" and d.get("vulnerable")]
    if not vuln:
        return
    g = full.subgraph(sys_nodes + vuln).copy()
    pos = nx.spring_layout(g, seed=42, k=0.55, iterations=200)
    fig, ax = plt.subplots(figsize=(13, 9))
    nx.draw_networkx_nodes(g, pos, nodelist=sys_nodes, node_shape="s",
                           node_color="#1c7ed6", node_size=1500, ax=ax)
    new = [n for n in vuln if n.replace("dep:", "", 1) in new_bases]
    old = [n for n in vuln if n.replace("dep:", "", 1) not in new_bases]
    nx.draw_networkx_nodes(g, pos, nodelist=old, node_color="#e03131",
                           node_size=320, ax=ax, edgecolors="black")
    nx.draw_networkx_nodes(g, pos, nodelist=new, node_color="#e03131",
                           node_size=360, ax=ax, edgecolors="#1c7ed6", linewidths=2.2)
    nx.draw_networkx_edges(g, pos, alpha=0.18, ax=ax)
    nx.draw_networkx_labels(g, pos, labels={n: g.nodes[n].get("label", n)
                            for n in sys_nodes}, font_size=9, font_color="white", ax=ax)
    nx.draw_networkx_labels(g, pos, labels={n: g.nodes[n].get("label", n)
                            for n in vuln}, font_size=6, ax=ax)
    ax.set_title("F6b. Shared dependencies with OpenMRS at O3-as-shipped scope "
                 "(red = shared & vulnerable; blue outline = surfaced only by the "
                 "wider scope)")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(config.PAPER_FIGURES_DIR / "F6b_shared_dependency_graph_o3wide.png", dpi=150)
    plt.close(fig)


def main() -> int:
    parse_common_args(__doc__)
    fig = config.PAPER_FIGURES_DIR
    fig.mkdir(parents=True, exist_ok=True)

    wide_repos = _wide_repo_slugs()
    log.info("OpenMRS wide scope: %d repos (core + O3 frontend + backend modules)", len(wide_repos))

    comps = _components_over_repos(wide_repos)
    vuln_map, vuln_details = _vuln_lookup(comps)
    wide_deps = _deps_from_repos(wide_repos, vuln_map, vuln_details)
    log.info("wide openmrs: %d deps (%d vulnerable)",
             len(wide_deps), sum(1 for d in wide_deps.values() if d["vuln_ids"]))

    core_per = _core_per_system()
    core_openmrs = core_per.get("openmrs", {})

    # Wide shared analysis: swap OpenMRS for its wide deps, keep the other four core.
    per_system = {sid: deps for sid, deps in core_per.items() if sid != "openmrs"}
    per_system["openmrs"] = wide_deps
    systems = config.load_systems()
    meta = {s.id: {"system_type": s.system_type, "display_name": s.display_name} for s in systems}
    shared_wide, graph_wide = analyze_shared(per_system, meta)

    core_shared = provenance.read_interim_json("shared_dependencies.json")
    core_sv = _shared_vuln_touching(core_shared, "openmrs")
    wide_sv = _shared_vuln_touching(shared_wide, "openmrs")
    new_sv = [b for b in wide_sv if b not in core_sv]

    # --- T3: core-vs-wide summary -------------------------------------------
    core_sum = _summarize(core_openmrs)
    wide_sum = _summarize(wide_deps)
    metrics = [
        ("OpenMRS source repos", len(config.get_system("openmrs").core_repos), len(wide_repos)),
        ("Total dependencies", core_sum["total_deps"], wide_sum["total_deps"]),
        ("  direct", core_sum["direct"], wide_sum["direct"]),
        ("  transitive", core_sum["transitive"], wide_sum["transitive"]),
        ("Vulnerable dependencies", core_sum["vulnerable"], wide_sum["vulnerable"]),
        ("  critical", core_sum["vuln_critical"], wide_sum["vuln_critical"]),
        ("  high", core_sum["vuln_high"], wide_sum["vuln_high"]),
        ("  medium", core_sum["vuln_medium"], wide_sum["vuln_medium"]),
        ("Shared-vulnerable nodes touching OpenMRS", len(core_sv), len(wide_sv)),
    ]
    _write_csv(fig / "T3_o3_scope_sensitivity.csv",
               ["Metric", "Core (4 repos)", "O3 as-shipped"], metrics)

    # --- F6b: wide shared-vulnerable nodes, NEW ones flagged ----------------
    f6b = sorted(shared_wide, key=lambda r: (-r["n_systems"], r["package"]))
    f6b_rows = [[s["package"], s["ecosystem"], s["max_severity"],
                 ", ".join(s["systems"]), "yes" if s["purl_base"] in new_sv else ""]
                for s in f6b if s["is_vulnerable"]]
    _write_csv(fig / "F6b_shared_vulnerable_o3wide.csv",
               ["package", "ecosystem", "max_severity", "systems", "new_at_wide_scope"],
               f6b_rows)

    provenance.write_interim_json("o3wide_dependencies.json", list(wide_deps.values()))
    provenance.write_interim_json("o3wide_shared.json", shared_wide)
    provenance.write_interim_json("o3wide_graph.json", graph_wide)
    _render_graph(graph_wide, fig, set(new_sv))

    log.info("T3 written: deps %d->%d, vulnerable %d->%d, shared-vuln(OpenMRS) %d->%d",
             core_sum["total_deps"], wide_sum["total_deps"],
             core_sum["vulnerable"], wide_sum["vulnerable"], len(core_sv), len(wide_sv))
    if new_sv:
        log.info("NEW shared-vulnerable nodes at wide scope: %s",
                 ", ".join(wide_sv[b]["package"] for b in new_sv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
