"""Acquire disclosed CVEs from the NVD CVE API 2.0 (Construct B).

CVE-to-product matching is the central hazard. We query two ways and
record a per-CVE ``match_confidence``:

  * **CPE match** (``virtualMatchString`` = a hand-validated CPE hint): the CVE's
    CPE configuration names the product -> confidence ``high``.
  * **Keyword match** (``keywordSearch`` = a system search term): broader recall,
    but a hit whose CPE configuration does *not* reference the product is only
    ``low`` confidence and is flagged for spot-validation -- never dropped.

A keyword hit is upgraded to ``high`` if its CPE configuration matches a hint's
vendor:product. Every raw query response is archived for provenance.
"""
from __future__ import annotations

import requests

from ..common import config, provenance
from ..common.cli import parse_common_args
from ..common.http import Client, nvd_client
from ..common.logging import get_logger

log = get_logger("cve_nvd")
SOURCE = "nvd"
PAGE_SIZE = 2000  # NVD max


def _vendor_product(cpe: str) -> tuple[str, str] | None:
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].lower(), parts[4].lower()
    return None


def _hint_vp(cpe_hints: list[str]) -> set[tuple[str, str]]:
    out = set()
    for h in cpe_hints:
        vp = _vendor_product(h)
        if vp:
            out.add(vp)
    return out


def _cpe_matches_hint(cve: dict, hint_vps: set[tuple[str, str]]) -> bool:
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                vp = _vendor_product(match.get("criteria", ""))
                if vp and vp in hint_vps:
                    return True
    return False


def _query_nvd(client: Client, params: dict) -> list[dict]:
    """Paginate an NVD query, returning the flat list of vulnerability wrappers."""
    url = config.endpoint("nvd_cve")
    out: list[dict] = []
    start = 0
    while True:
        q = dict(params, resultsPerPage=PAGE_SIZE, startIndex=start)
        data = client.get_json(url, params=q)
        vulns = data.get("vulnerabilities", []) or []
        out.extend(vulns)
        total = int(data.get("totalResults", 0))
        start += PAGE_SIZE
        if start >= total or not vulns:
            break
    return out


def collect_system(client: Client, system) -> dict:
    hint_vps = _hint_vp(system.cpe_hints)
    merged: dict[str, dict] = {}      # cve_id -> wrapper
    match_meta: dict[str, dict] = {}
    queries: list[dict] = []

    # 1) CPE-based queries (high confidence).
    for hint in system.cpe_hints:
        try:
            vulns = _query_nvd(client, {"virtualMatchString": hint})
        except (requests.RequestException, ValueError) as exc:
            log.warning("NVD CPE query failed for %s (%s): %s", system.id, hint, exc)
            continue
        queries.append({"method": "cpe", "query": hint, "count": len(vulns)})
        for w in vulns:
            cid = w["cve"]["id"]
            merged.setdefault(cid, w)
            match_meta[cid] = {"match_method": "cpe", "match_confidence": "high",
                               "matched_hint": hint}

    # 2) Keyword queries (recall; confidence depends on CPE corroboration).
    for term in system.ghsa_search_terms:
        try:
            vulns = _query_nvd(client, {"keywordSearch": term})
        except (requests.RequestException, ValueError) as exc:
            log.warning("NVD keyword query failed for %s (%s): %s", system.id, term, exc)
            continue
        queries.append({"method": "keyword", "query": term, "count": len(vulns)})
        for w in vulns:
            cid = w["cve"]["id"]
            merged.setdefault(cid, w)
            if cid in match_meta and match_meta[cid]["match_method"] == "cpe":
                continue  # already high
            corroborated = _cpe_matches_hint(w["cve"], hint_vps) if hint_vps else False
            match_meta[cid] = {
                "match_method": "keyword",
                "match_confidence": "high" if corroborated else "low",
                "matched_hint": term,
            }

    return {
        "system_id": system.id,
        "cpe_hints": system.cpe_hints,
        "queries": queries,
        "vulnerabilities": list(merged.values()),
        "match_meta": match_meta,
        "n_total": len(merged),
        "n_high": sum(1 for m in match_meta.values() if m["match_confidence"] == "high"),
        "n_low": sum(1 for m in match_meta.values() if m["match_confidence"] == "low"),
        "snapshot_date": config.snapshot_date(),
    }


def main() -> int:
    args = parse_common_args(__doc__)
    client = nvd_client()
    if not config.nvd_api_key():
        log.warning("NVD_API_KEY not set: NVD limits to ~5 req/30s; this will be slow.")
    failures: list[dict] = []
    for system in config.load_systems():
        if args.only and system.id != args.only:
            continue
        name = f"{system.id}.json"
        if provenance.raw_exists(SOURCE, name) and not args.refresh:
            log.info("skip (cached): %s", name)
            continue
        try:
            rec = collect_system(client, system)
            ptr = provenance.write_json(SOURCE, name, rec)
            log.info("ok %s -> %s (total=%d high=%d low=%d)",
                     system.id, ptr, rec["n_total"], rec["n_high"], rec["n_low"])
        except (requests.RequestException, ValueError) as exc:
            log.error("FAILED NVD %s: %s", system.id, exc)
            failures.append({"system_id": system.id, "error": str(exc)})

    if failures:
        provenance.write_json(SOURCE, "_failures.json", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
