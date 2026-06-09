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
    ax.set_title("F1. OpenSSF Scorecard by check (n/a = not assessable on Codeberg)")
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
    ax.set_title("F2. Disclosed-CVE landscape by severity (note the asymmetry)")
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
    ax.set_title("F2b. Disclosed CVEs per year")
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
    ax.set_title("F3. Vulnerability-class mix (OWASP Top-10:2021)")
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
    ax.set_title("F4. Remediation latency where determinable (opportunistic)")
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
    ax.set_title("F5. Dependency vulnerabilities: direct vs transitive, by severity")
    ax.legend(title="severity", fontsize=8)
    plt.xticks(rotation=0, fontsize=8)
    _save(fig, "F5_dependency_vuln")


# --- F6 (centerpiece) ------------------------------------------------------ #
def fig_shared_graph(_t):
    data = provenance.read_interim_json("dependency_graph.json") \
        if (config.INTERIM_DIR / "dependency_graph.json").exists() else None
    if not data or not data.get("nodes"):
        return _placeholder("F6_shared_dependency_graph", "no shared deps (run acquire)")
    g = nx.node_link_graph(data, edges="links")
    dep_nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == "dependency"]
    if not dep_nodes:
        return _placeholder("F6_shared_dependency_graph",
                            "no dependencies shared across >1 system")
    sys_nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == "system"]
    pos = nx.spring_layout(g, seed=42, k=0.6, iterations=200)
    fig, ax = plt.subplots(figsize=(11, 8))
    nx.draw_networkx_nodes(g, pos, nodelist=sys_nodes, node_shape="s",
                           node_color="#1c7ed6", node_size=1400, ax=ax)
    vuln = [n for n in dep_nodes if g.nodes[n].get("vulnerable")]
    safe = [n for n in dep_nodes if not g.nodes[n].get("vulnerable")]
    nx.draw_networkx_nodes(g, pos, nodelist=safe, node_color="#ced4da",
                           node_size=220, ax=ax)
    nx.draw_networkx_nodes(g, pos, nodelist=vuln, node_color="#e03131",
                           node_size=380, ax=ax, edgecolors="black")
    nx.draw_networkx_edges(g, pos, alpha=0.25, ax=ax)
    nx.draw_networkx_labels(g, pos, labels={n: g.nodes[n].get("label", n)
                            for n in sys_nodes}, font_size=9, font_color="white", ax=ax)
    nx.draw_networkx_labels(g, pos, labels={n: g.nodes[n].get("label", n)
                            for n in vuln}, font_size=7, ax=ax)
    ax.set_title("F6. Dependencies shared across EHRs (red = shared & vulnerable: "
                 "cross-system single points of failure)")
    ax.axis("off")
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
