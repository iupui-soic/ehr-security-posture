"""Render F1-F6 to paper/figures/ (deterministic; robust to not-yet-acquired data).

F1 Scorecard heatmap (not-assessable cells hatched) | F2 CVEs by severity per
system + F2b CVEs/year | F3 OWASP class mix | F4 remediation latency (optional) |
F5 dependency vulns direct-vs-transitive by severity, grouped by system_type |
F6 shared-dependency network (shared *vulnerable* nodes highlighted) -- centerpiece.
"""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402
import networkx as nx  # noqa: E402
import numpy as np  # noqa: E402

from ..common import config, provenance  # noqa: E402
from ..common.cli import parse_common_args  # noqa: E402
from ..common.logging import get_logger  # noqa: E402
from . import comparisons as cmp  # noqa: E402
from . import loaders  # noqa: E402

log = get_logger("figures")

SEV_COLOR = {"critical": "#7d0a0a", "high": "#e8590c", "medium": "#f59f00",
             "low": "#74b816", "none": "#dee2e6"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
# Deterministic top-to-bottom ordering of the system column (maven-heavy systems
# near the top, npm-heavy Medplum near the bottom) to minimise edge crossings.
SYS_ORDER = ["sys:ehrbase", "sys:openmrs", "sys:openemr", "sys:medplum",
             "sys:gnuhealth"]
DPI = 150


def _save(fig, name: str):
    config.PAPER_FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(config.PAPER_FIGURES_DIR / f"{name}.png", dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s.png", name)


def _placeholder(name: str, msg: str):
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.text(0.5, 0.5, f"{name}\n{msg}", ha="center", va="center", fontsize=11,
            color="#868e96", wrap=True)
    ax.axis("off")
    _save(fig, name)


# --- F1 -------------------------------------------------------------------- #
def fig_scorecard(t):
    mat = cmp.scorecard_matrix(t)
    if mat.empty:
        return _placeholder("F1_scorecard_heatmap", "no Scorecard data (run acquire)")
    na = cmp.not_assessable_mask(t).reindex(index=mat.index, columns=mat.columns)
    fig, ax = plt.subplots(figsize=(1.6 + 0.9 * len(mat.columns), 0.45 * len(mat.index) + 1))
    data = mat.to_numpy(dtype=float)
    im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=10, aspect="auto")
    ax.set_xticks(range(len(mat.columns)))
    ax.set_xticklabels(mat.columns, rotation=30, ha="right")
    ax.set_yticks(range(len(mat.index)))
    ax.set_yticklabels(mat.index)
    for i in range(len(mat.index)):
        for j in range(len(mat.columns)):
            v = data[i, j]
            is_na = bool(na.to_numpy()[i, j]) if not na.empty else False
            if is_na or np.isnan(v):
                ax.add_patch(plt.Rectangle((j - .5, i - .5), 1, 1, fill=True,
                             color="#f1f3f5", hatch="//", ec="#adb5bd"))
                ax.text(j, i, "n/a", ha="center", va="center", fontsize=7, color="#868e96")
            else:
                ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8,
                        color="black")
    fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02, label="Scorecard 0-10")
    _save(fig, "F1_scorecard_heatmap")


# --- F2 -------------------------------------------------------------------- #
def fig_cve_severity(t):
    c = cmp.cve_severity_counts(t)
    if c.empty:
        return _placeholder("F2_cve_severity", "no disclosed CVEs matched (run acquire)")
    c = loaders.order_systems(c.reset_index()).set_index("system_id")
    fig, ax = plt.subplots(figsize=(7, 4))
    bottom = np.zeros(len(c))
    for sev in ["critical", "high", "medium", "low", "none"]:
        if sev in c.columns:
            ax.bar(c.index.astype(str), c[sev], bottom=bottom,
                   color=SEV_COLOR[sev], label=sev)
            bottom += c[sev].to_numpy()
    ax.set_ylabel("disclosed CVEs")
    ax.legend(title="severity", fontsize=8)
    plt.xticks(rotation=20, ha="right")
    _save(fig, "F2_cve_severity")


def fig_cve_by_year(t):
    y = cmp.cve_by_year(t)
    if y.empty:
        return
    fig, ax = plt.subplots(figsize=(7, 4))
    for col in [c for c in loaders.SYSTEM_ORDER if c in y.columns]:
        ax.plot(y.index.astype(int), y[col], marker="o", label=col)
    ax.set_xlabel("year"); ax.set_ylabel("disclosed CVEs")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=8)
    _save(fig, "F2b_cve_by_year")


# --- F3 -------------------------------------------------------------------- #
def fig_owasp(t):
    o = cmp.owasp_distribution(t)
    if o.empty:
        return _placeholder("F3_owasp_distribution", "no classified CVEs (run acquire)")
    o = o.reindex(columns=[s for s in loaders.SYSTEM_ORDER if s in o.columns])
    fig, ax = plt.subplots(figsize=(8, 0.5 * len(o.index) + 2))
    bottom = np.zeros(len(o.index))
    cmap = plt.get_cmap("tab10")
    for k, col in enumerate(o.columns):
        ax.barh(o.index, o[col], left=bottom, color=cmap(k % 10), label=col)
        bottom += o[col].to_numpy()
    ax.set_xlabel("CVE count")
    ax.legend(fontsize=8, ncol=2)
    _save(fig, "F3_owasp_distribution")


# --- F4 (optional) --------------------------------------------------------- #
def fig_latency(t):
    v = t["disclosed_vuln"]
    if v.empty or "remediation_days" not in v or v["remediation_days"].dropna().empty:
        return  # opportunistic; skip silently when undeterminable
    fig, ax = plt.subplots(figsize=(7, 4))
    for sid in [s for s in loaders.SYSTEM_ORDER if s in v["system_id"].unique()]:
        d = v[v["system_id"] == sid]["remediation_days"].dropna()
        if not d.empty:
            ax.scatter([sid] * len(d), d, alpha=0.6)
    ax.axhline(0, color="#adb5bd", lw=0.8)
    ax.set_ylabel("days (fix release - disclosure)")
    plt.xticks(rotation=20, ha="right")
    _save(fig, "F4_remediation_latency")


# --- F5 -------------------------------------------------------------------- #
def fig_dependency_vuln(t):
    d = cmp.dependency_vuln_counts(t)
    if d.empty:
        return _placeholder("F5_dependency_vuln", "no dependency vulns (run acquire)")
    sev_cols = [c for c in ["critical", "high", "medium", "low"] if c in d.columns]
    d = d.copy()
    d["label"] = d["system_id"].astype(str) + "\n" + d["scope"]
    fig, ax = plt.subplots(figsize=(1.0 * len(d) + 3, 4))
    bottom = np.zeros(len(d))
    for sev in sev_cols:
        ax.bar(d["label"], d[sev], bottom=bottom, color=SEV_COLOR[sev], label=sev)
        bottom += d[sev].to_numpy()
    ax.set_ylabel("vulnerable dependencies")
    ax.legend(title="severity", fontsize=8)
    plt.xticks(rotation=0, fontsize=8)
    _save(fig, "F5_dependency_vuln")


# --- F6 (centerpiece) ------------------------------------------------------ #
def shared_bipartite_fig(g, title, new_bases=None, figsize=(7.4, 6.6),
                         label_size=7.0, reachable_only=False):
    """Deterministic bipartite view of shared *vulnerable* dependencies:
    Maven (and other non-npm) packages in a left column, systems in the centre,
    npm packages on the right; edges + nodes coloured by max severity. Non-
    vulnerable shared deps and systems with no shared-vulnerable edge are dropped
    (this is what removes the unreadable force-directed "hairball"). ``new_bases``
    (purl_base set) outlines nodes surfaced only at a wider scope (F6b).
    With ``reachable_only`` the figure keeps only edges to systems that genuinely
    reach the dependency (node attr ``reachable_systems``) and only nodes that are
    reachable in >=2 systems, i.e. true reachable cross-system SPOFs.
    Returns a matplotlib Figure, or None when there is nothing to draw.
    """
    from matplotlib.lines import Line2D
    new_bases = new_bases or set()
    all_sys = [n for n, d in g.nodes(data=True) if d.get("kind") == "system"]
    vuln = [n for n, d in g.nodes(data=True)
            if d.get("kind") == "dependency" and d.get("vulnerable")]
    if reachable_only:
        vuln = [n for n in vuln
                if len(g.nodes[n].get("reachable_systems") or []) >= 2]
    if not vuln:
        return None
    sub = g.subgraph(all_sys + vuln).copy()
    if reachable_only:  # drop edges to systems that do not genuinely reach the dep
        for d in vuln:
            reach = set(g.nodes[d].get("reachable_systems") or [])
            for s in [nb for nb in sub.neighbors(d)
                      if sub.nodes[nb].get("kind") == "system"]:
                if s.replace("sys:", "", 1) not in reach:
                    sub.remove_edge(s, d)
    sys_nodes = [n for n in all_sys if sub.degree(n) > 0]
    sys_nodes.sort(key=lambda n: (SYS_ORDER.index(n) if n in SYS_ORDER else 99, n))

    def _is_npm(n):
        return (sub.nodes[n].get("ecosystem") or "") == "npm"

    def _skey(n):
        d = sub.nodes[n]
        return (SEV_RANK.get(d.get("max_severity"), 5),
                -d.get("n_systems", 0), d.get("label", n))

    left = sorted((n for n in vuln if not _is_npm(n)), key=_skey)
    right = sorted((n for n in vuln if _is_npm(n)), key=_skey)

    def _col(nodes, x):
        m = max(len(nodes), 1)
        return {n: (x, 1.0 - (i + 0.5) / m) for i, n in enumerate(nodes)}

    pos = {**_col(left, 0.0), **_col(sys_nodes, 1.0), **_col(right, 2.0)}

    fig, ax = plt.subplots(figsize=figsize)
    edgelist, ecolors = [], []
    for u, v in sub.edges():
        dep = u if sub.nodes[u].get("kind") == "dependency" else v
        other = v if dep == u else u
        if dep not in pos or other not in pos:
            continue
        edgelist.append((u, v))
        ecolors.append(SEV_COLOR.get(sub.nodes[dep].get("max_severity"), "#ced4da"))
    nx.draw_networkx_edges(sub, pos, edgelist=edgelist, edge_color=ecolors,
                           alpha=0.55, width=1.0, ax=ax)
    nx.draw_networkx_nodes(sub, pos, nodelist=sys_nodes, node_shape="s",
                           node_color="#1c7ed6", node_size=1500, ax=ax)
    deps = left + right
    dcolors = [SEV_COLOR.get(sub.nodes[n].get("max_severity"), "#ced4da") for n in deps]
    dsizes = [170 + 90 * (max(sub.degree(n), 1) - 1) for n in deps]
    is_new = [n.replace("dep:", "", 1) in new_bases for n in deps]
    edgecols = ["#1c7ed6" if nw else "black" for nw in is_new]
    lws = [2.2 if nw else 0.6 for nw in is_new]
    nx.draw_networkx_nodes(sub, pos, nodelist=deps, node_color=dcolors,
                           node_size=dsizes, edgecolors=edgecols, linewidths=lws, ax=ax)
    nx.draw_networkx_labels(sub, pos, labels={n: sub.nodes[n].get("label", n)
                            for n in sys_nodes}, font_size=6.5,
                            font_color="black", ax=ax)
    for n in left:
        x, y = pos[n]
        ax.text(x - 0.11, y, sub.nodes[n].get("label", n), ha="right", va="center",
                fontsize=label_size)
    for n in right:
        x, y = pos[n]
        ax.text(x + 0.11, y, sub.nodes[n].get("label", n), ha="left", va="center",
                fontsize=label_size)
    if left:
        ax.text(0.0, 1.05, "Maven", ha="center", va="bottom", fontsize=9, fontweight="bold")
    if right:
        ax.text(2.0, 1.05, "npm", ha="center", va="bottom", fontsize=9, fontweight="bold")
    handles = [Line2D([0], [0], marker="o", color="w", markersize=8,
               markerfacecolor=SEV_COLOR[s], label=s)
               for s in ("critical", "high", "medium") if any(
                   sub.nodes[n].get("max_severity") == s for n in deps)]
    if new_bases:
        handles.append(Line2D([0], [0], marker="o", color="w", markersize=8,
                       markerfacecolor="#e9ecef", markeredgecolor="#1c7ed6",
                       markeredgewidth=2, label="new at wide scope"))
    if handles:
        ax.legend(handles=handles, loc="lower center", ncol=len(handles),
                  fontsize=7, frameon=False, bbox_to_anchor=(0.5, -0.05))
    if title:
        ax.set_title(title, fontsize=10)
    ax.set_xlim(-1.0, 3.0)
    ax.set_ylim(-0.10, 1.13)
    ax.axis("off")
    return fig


def fig_shared_graph(_t):
    data = provenance.read_interim_json("dependency_graph.json") \
        if (config.INTERIM_DIR / "dependency_graph.json").exists() else None
    if not data or not data.get("nodes"):
        return _placeholder("F6_shared_dependency_graph", "no shared deps (run acquire)")
    g = nx.node_link_graph(data, edges="links")
    fig = shared_bipartite_fig(g, "", reachable_only=True)
    if fig is None:
        return _placeholder("F6_shared_dependency_graph",
                            "no reachable cross-system shared-vulnerable deps")
    _save(fig, "F6_shared_dependency_graph")


def main() -> int:
    parse_common_args(__doc__)
    t = loaders.load_all()
    fig_scorecard(t)
    fig_cve_severity(t)
    fig_cve_by_year(t)
    fig_owasp(t)
    fig_latency(t)
    fig_dependency_vuln(t)
    fig_shared_graph(t)
    log.info("figures complete -> %s", config.PAPER_FIGURES_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
