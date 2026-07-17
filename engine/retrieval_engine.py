"""
retrieval_engine.py
===================
Stage B of the Furix deterministic pipeline — the Crosswalk and Retrieval Engine.

Responsibilities:
  - Graph query helpers: expand CIS controls to NIST mappings and related
    controls via Apache AGE (graph_expand_controls, enrich_results_with_graph).
  - HIPAA signal mapping: translate log findings → HIPAA CFR sections via
    three signal paths: CIS→NIST→CSF prefix, MITRE tactics, behavioral booleans
    (map_log_to_hipaa_specs).
  - pgvector retrieval: scoped CIS + NIST + HIPAA chunk retrieval using
    SecureBERT embeddings and cosine similarity.
  - Reranking: SecureBERT cross-encoder rerank with per-framework guaranteed
    slot allocation (_stage3_rerank_with_nist_guarantee).
  - Main retrieval entry point: retrieve_cis_controls_llm() — called from
    pipeline.py after detection_engine.py produces findings.

CIS_TO_NIST_MAPPINGS used here comes from furix_det (SCF 2026.1 source).

Imports from: config.py, db_connections.py, setup_ingestion.py, detection_engine.py
"""

import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import (
    AGE_GRAPH_NAME, PG_TABLE,
    COVERAGE_SCORE_FLOOR, CROSS_CONTROL_THRESHOLD,
    TOP_K, TOP_K_RERANK, TOP_K_PER_CTRL,
    NIST_GUARANTEED, CIS_GUARANTEED, HIPAA_GUARANTEED,
    QUALITY_FILTER_WINDOW, ACTION_WORDS,
)
from db_connections import (
    get_pg_connection, get_age_read_connection,
    CIS_TO_NIST_MAPPINGS, HIPAA_TO_NIST_MAPPINGS,
)
from models import embedder, reranker
from hipaa_data import (
    CSF_TO_HIPAA_SPECS, HIPAA_SPEC_REGISTRY,
    MITRE_TACTIC_TO_CSF, BEHAVIOR_TO_HIPAA_SPEC,
)
from detection_engine import (
    _CONTROL_SENTENCES, _NIST_CATEGORY_SENTENCES,
    build_per_control_queries_from_llm, _build_fallback_query,
)

def get_nist_mappings_for_control(ctrl_id: str) -> list:
    """
    Queries AGE for all NIST subcategory IDs mapped to a given CIS control.
    Returns list of (nist_id, function_id) tuples.
    e.g. [("PR.AA-01", "PR"), ("PR.AA-03", "PR"), ("PR.AA-05", "PR")]
    """
    try:
        conn = get_age_read_connection()
        cur  = conn.cursor()
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH (c:Control {{id: '{ctrl_id}'}})-[:MAPS_TO]->(n:NISTCategory)
                RETURN n.id, n.function_id
            $$) AS (nist_id agtype, function_id agtype);
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        # Strip AGE's surrounding quotes from agtype strings
        return [
            (str(r[0]).strip('"'), str(r[1]).strip('"'))
            for r in rows
        ]
    except Exception as e:
        print(f"[graph] get_nist_mappings_for_control({ctrl_id}) failed: {e}")
        return []


def get_related_controls(ctrl_id: str) -> list:
    """
    Queries AGE for CIS controls with a RELATED_TO edge from the given control.
    Returns list of related control IDs.
    e.g. ["Control 12", "Control 5"]
    """
    try:
        conn = get_age_read_connection()
        cur  = conn.cursor()
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH (a:Control {{id: '{ctrl_id}'}})-[:RELATED_TO]->(b:Control)
                RETURN b.id
            $$) AS (related_id agtype);
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [str(r[0]).strip('"') for r in rows]
    except Exception as e:
        print(f"[graph] get_related_controls({ctrl_id}) failed: {e}")
        return []


_GRAPH_EXPANSION_CACHE: dict = {}   # module-level cache; survives across pipeline calls

def graph_expand_controls(control_ids: list) -> dict:
    """
    Batched version — 2 queries total instead of 2*N queries.
    Results are cached by sorted control_ids tuple so repeated calls
    (e.g. benchmark loop with same controls) never hit the DB twice.
    """
    if not control_ids:
        return {}

    cache_key = tuple(sorted(control_ids))
    if cache_key in _GRAPH_EXPANSION_CACHE:
        return _GRAPH_EXPANSION_CACHE[cache_key]

    expansion = {c: {"nist_mappings": [], "related_controls": []} for c in control_ids}

    try:
        conn = get_age_read_connection()
        cur  = conn.cursor()

        # Single query for ALL NIST mappings across all controls
        ids_str = ", ".join(f"'{c}'" for c in control_ids)
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH (c:Control)-[:MAPS_TO]->(n:NISTCategory)
                WHERE c.id IN [{ids_str}]
                RETURN c.id, n.id, n.function_id
            $$) AS (ctrl_id agtype, nist_id agtype, function_id agtype);
        """)
        for row in cur.fetchall():
            ctrl = str(row[0]).strip('"')
            nist = str(row[1]).strip('"')
            func = str(row[2]).strip('"')
            if ctrl in expansion:
                expansion[ctrl]["nist_mappings"].append((nist, func))

        # Single query for ALL related controls
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH (a:Control)-[:RELATED_TO]->(b:Control)
                WHERE a.id IN [{ids_str}]
                RETURN a.id, b.id
            $$) AS (src_id agtype, dst_id agtype);
        """)
        for row in cur.fetchall():
            src = str(row[0]).strip('"')
            dst = str(row[1]).strip('"')
            if src in expansion:
                expansion[src]["related_controls"].append(dst)

        cur.close()
        conn.close()

    except Exception as e:
        print(f"[graph] graph_expand_controls batch failed: {e}")

    _GRAPH_EXPANSION_CACHE[cache_key] = expansion
    return expansion


def enrich_results_with_graph(
    final_results: list,
    graph_expansion: dict,
) -> list:
    """
    Attaches graph context to each result tuple.
    - CIS results   : nist_mappings from AGE graph MAPS_TO edges
    - NIST results  : nist_mappings = the result itself (it IS a NIST subcategory)
    - HIPAA results : nist_mappings from csf metadata field
    """
    enriched = []
    for score, doc, meta in final_results:
        ctrl_id   = meta.get("control_id",   "")
        framework = meta.get("framework_id", "cis_v8")
        new_meta  = dict(meta)

        if framework == "cis_v8":
            ctx = graph_expansion.get(ctrl_id, {})
            new_meta["nist_mappings"]    = ctx.get("nist_mappings",    [])
            new_meta["related_controls"] = ctx.get("related_controls", [])

        elif framework == "nist_csf":
            sfg_id = meta.get("safeguard_id") or ctrl_id
            func   = sfg_id.split(".")[0] if sfg_id else ""
            new_meta["nist_mappings"]    = [(sfg_id, func)] if sfg_id else []
            new_meta["related_controls"] = []

        elif framework == "hipaa_security_rule":
            csf_list = meta.get("csf", [])
            new_meta["nist_mappings"]    = [(c, c.split(".")[0]) for c in csf_list]
            new_meta["related_controls"] = []

        enriched.append((score, doc, new_meta))
    return enriched


print("✅ Graph expansion helpers defined")
print("   get_nist_mappings_for_control() | get_related_controls()")
print("   graph_expand_controls()         | enrich_results_with_graph()")

def get_pg_doc_count(framework_id: str = None) -> int:
    conn = get_pg_connection()
    cur  = conn.cursor()
    if framework_id:
        cur.execute(f"SELECT COUNT(*) FROM {PG_TABLE} WHERE framework_id = %s;", (framework_id,))
    else:
        cur.execute(f"SELECT COUNT(*) FROM {PG_TABLE};")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count

# %%
def _stage3_rerank_with_nist_guarantee(
    dedup_docs, dedup_metas, dedup_queries,
    investigation_query, mapped_controls, graph_expansion,
    reranker,
):
    """
    Stage 3: rerank + coverage guarantee + guaranteed NIST slots.
    Returns final enriched list of (score, doc, meta).
    """
    sep = "=" * 72
    if not dedup_docs:

        print("[RAG] No documents survived retrieval")

        return [], set()

    if not dedup_metas:

        print("[RAG] No metadata survived retrieval")

        return [], set()
    # ── Rerank ────────────────────────────────────────────────────────────────
    # Cell 9 — replace the two predict() calls at the top of _stage3_rerank_with_nist_guarantee()

    # Build both pair sets and score in ONE batch call
    ctrl_pairs   = [[q, d] for q, d in zip(dedup_queries, dedup_docs)]
    global_pairs = [[investigation_query, d] for d in dedup_docs]
    all_pairs    = ctrl_pairs + global_pairs

    _t_predict = time.perf_counter()
    all_scores = reranker.predict(all_pairs)
    print(f"  [timing] 3_rerank_predict_only={time.perf_counter() - _t_predict:.4f}s "
          f"({len(all_pairs)} pairs)")

    if all_scores is None:
        raise ValueError("Empty reranker output")

    if len(all_scores) != len(all_pairs):
        raise ValueError(
            f"Reranker returned {len(all_scores)} scores "
            f"for {len(all_pairs)} pairs"
        )

    n = len(dedup_docs)
    scores = []

    for i in range(n):

        try:
            ctrl_score = float(all_scores[i])
        except Exception:
            ctrl_score = 0.0

        try:
            global_score = float(all_scores[n + i])
        except Exception:
            global_score = 0.0

        scores.append(max(ctrl_score, global_score))
    scored = sorted(
        zip(scores, dedup_docs, dedup_metas),
        key=lambda x: x[0], reverse=True
    )

    # ── Split into framework pools ────────────────────────────────────────────
    cis_scored   = [(s, d, m) for s, d, m in scored
                    if m.get("framework_id", "cis_v8") == "cis_v8"]
    nist_scored  = [(s, d, m) for s, d, m in scored
                    if m.get("framework_id") == "nist_csf"]
    hipaa_scored = [(s, d, m) for s, d, m in scored
                    if m.get("framework_id") == "hipaa_security_rule"]

    # ── Coverage guarantee (CIS pool only) ───────────────────────────────────
    guaranteed:   list = []
    remaining:    list = []
    covered_ctrl: set  = set()

    for score, doc, meta in cis_scored:
        ctrl = meta.get("control_id", "General")
        if ctrl in mapped_controls and ctrl not in covered_ctrl:
            guaranteed.append((score, doc, meta))
            covered_ctrl.add(ctrl)
        else:
            remaining.append((score, doc, meta))

    boosted_guaranteed = [
        (max(float(s), COVERAGE_SCORE_FLOOR), d, m)
        for s, d, m in guaranteed
    ]
    filtered_remaining = [
        (s, d, m) for s, d, m in remaining
        if m.get("control_id", "General") in mapped_controls
        or float(s) >= CROSS_CONTROL_THRESHOLD
    ]
    cis_combined = sorted(
        boosted_guaranteed + filtered_remaining,
        key=lambda x: x[0], reverse=True
    )

    # ── Guaranteed NIST slots ─────────────────────────────────────────────────
    NIST_SCORE_FLOOR = 0.40
    nist_final:    list = []
    seen_nist_sfg: set  = set()
    # Pass 1: score-gated fill
    for score, doc, meta in nist_scored:
        sfg = meta.get("safeguard_id", "") or meta.get("control_id", "")
        if sfg and sfg not in seen_nist_sfg and float(score) >= NIST_SCORE_FLOOR:
            seen_nist_sfg.add(sfg)
            nist_final.append((score, doc, meta))
        if len(nist_final) >= NIST_GUARANTEED:
            break
    # Pass 2: fill remaining slots without floor (guarantees minimum count)
    if len(nist_final) < NIST_GUARANTEED:
        for score, doc, meta in nist_scored:
            sfg = meta.get("safeguard_id", "") or meta.get("control_id", "")
            if sfg and sfg not in seen_nist_sfg:
                seen_nist_sfg.add(sfg)
                nist_final.append((score, doc, meta))
            if len(nist_final) >= NIST_GUARANTEED:
                break

    # ── Guaranteed HIPAA slots ────────────────────────────────────────────────
    HIPAA_SCORE_FLOOR = 0.68
    hipaa_final:    list = []
    seen_hipaa_sfg: set  = set()
    # Pass 1: score-gated fill — blocks low-relevance contingency specs
    for score, doc, meta in hipaa_scored:
        sfg = meta.get("safeguard_id", "") or meta.get("control_id", "")
        if sfg and sfg not in seen_hipaa_sfg and float(score) >= HIPAA_SCORE_FLOOR:
            seen_hipaa_sfg.add(sfg)
            hipaa_final.append((score, doc, meta))
        if len(hipaa_final) >= HIPAA_GUARANTEED:
            break
    # Pass 2: fill remaining without floor
    if len(hipaa_final) < HIPAA_GUARANTEED:
        for score, doc, meta in hipaa_scored:
            sfg = meta.get("safeguard_id", "") or meta.get("control_id", "")
            if sfg and sfg not in seen_hipaa_sfg:
                seen_hipaa_sfg.add(sfg)
                hipaa_final.append((score, doc, meta))
            if len(hipaa_final) >= HIPAA_GUARANTEED:
                break

    # ── Guaranteed CIS slots (mirrors NIST/HIPAA guarantee logic) ────────────
    # First, fill CIS_GUARANTEED slots with one unique control each.
    # Then backfill remaining budget with the rest of cis_combined.
    cis_guaranteed_final: list = []
    seen_cis_ctrl:        set  = set()
    for score, doc, meta in cis_combined:
        ctrl = meta.get("control_id", "")
        if ctrl and ctrl not in seen_cis_ctrl:
            seen_cis_ctrl.add(ctrl)
            cis_guaranteed_final.append((score, doc, meta))
        if len(cis_guaranteed_final) >= CIS_GUARANTEED:
            break

    # Fill any remaining budget up to TOP_K_RERANK
    guaranteed_cis_ids = {id(doc) for _, doc, _ in cis_guaranteed_final}
    cis_extra = [
        (s, d, m) for s, d, m in cis_combined
        if id(d) not in guaranteed_cis_ids
    ]
    cis_slots = TOP_K_RERANK - len(nist_final) - len(hipaa_final)
    cis_final = (cis_guaranteed_final + cis_extra)[:max(cis_slots, 0)]

    # ── Merge all three frameworks, sort by score ─────────────────────────────
    # Keep guaranteed framework slots first
    guaranteed_results = sorted(
        nist_final[:NIST_GUARANTEED] +
        hipaa_final[:HIPAA_GUARANTEED] +
        cis_guaranteed_final[:CIS_GUARANTEED],
        key=lambda x: x[0], reverse=True
    )

    guaranteed_ids = {id(doc) for _, doc, _ in guaranteed_results}

    remaining_pool = [
        item
        for item in (cis_final + nist_final + hipaa_final)
        if id(item[1]) not in guaranteed_ids
    ]

    remaining_pool.sort(
        key=lambda x: x[0],
        reverse=True
    )

    remaining_budget = max(
        0,
        TOP_K_RERANK - len(guaranteed_results)
    )

    combined_final = (
        guaranteed_results +
        remaining_pool[:remaining_budget]
    )

    # ── Enrich with graph context ─────────────────────────────────────────────
    if graph_expansion is None:
        graph_expansion = {}

    try:
        final = enrich_results_with_graph(
            combined_final,
            graph_expansion
        )
    except Exception as e:

        print(f"[graph enrichment] failed: {e}")

        final = combined_final
    guaranteed_docs = {id(doc) for _, doc, _ in boosted_guaranteed}

    # ── Diagnostics ───────────────────────────────────────────────────────────
    n_cis   = sum(1 for _, _, m in final if m.get("framework_id","cis_v8") == "cis_v8")
    n_nist  = sum(1 for _, _, m in final if m.get("framework_id") == "nist_csf")
    n_hipaa = sum(1 for _, _, m in final if m.get("framework_id") == "hipaa_security_rule")
    print(f"  CIS results in final   : {n_cis}  (guaranteed min: {CIS_GUARANTEED})")
    print(f"  NIST results in final  : {n_nist}  (guaranteed min: {NIST_GUARANTEED})")
    print(f"  HIPAA results in final : {n_hipaa} (guaranteed min: {HIPAA_GUARANTEED})")

    return final, guaranteed_docs


print("✅ _stage3_rerank_with_nist_guarantee() updated — CIS + NIST + HIPAA slots")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — RAG Retrieval Pipeline v8 (Phases 2a–3)
# ─────────────────────────────────────────────────────────────────────────────
# ── Pre-compile once at module level ─────────────────────────────────────────
_SAFEGUARD_PREFIX_RE = re.compile(
    r"Safeguard\s+\d+\.\d+|^\d+\.\d+\s*[:\-–]",
    re.MULTILINE
)


def _is_quality_chunk(doc: str, meta: dict = None) -> bool:
    if meta:
        sfg_id      = meta.get("safeguard_id", "")
        framework   = meta.get("framework_id", "cis_v8")
        if sfg_id:
            header_zone = doc[:400]
            if framework == "cis_v8":
                # CIS format: "Safeguard 6.2: ..."
                if not re.search(
                    rf"Safeguard\s+{re.escape(sfg_id)}|^{re.escape(sfg_id)}\s*[:\-–]",
                    header_zone, re.MULTILINE
                ):
                    return False

            elif framework == "hipaa_security_rule":
                # JSON chunks start with "HIPAA <category> — <standard>: <spec>"
                # sfg_id is a spec code like "AS-WS-AS" which never appears in content.
                # Instead just verify it looks like a HIPAA chunk and has action words.
                if not re.search(r"HIPAA\s+(Administrative|Physical|Technical|Organizational|Policies)",
                                 header_zone, re.IGNORECASE):
                    return False
                return True
        
            else:
                # NIST format: "GV.OC-01: ..." or "PR.AA-01 ..."
                if not re.search(
                    rf"{re.escape(sfg_id)}\s*[:\-–\s]",
                    header_zone, re.MULTILINE | re.IGNORECASE
                ):
                    return False
            window = doc[:600].lower()
            return any(w in window for w in ACTION_WORDS)

    first_n = doc[:QUALITY_FILTER_WINDOW].lower()
    return any(w in first_n for w in ACTION_WORDS)

def map_log_to_hipaa_specs(findings: dict) -> tuple:
    """
    3-signal-path mapper: log findings → specific HIPAA spec codes → CFR sections.
    Signal 1: CIS controls → CIS_TO_NIST_MAPPINGS → CSF prefix → CSF_TO_HIPAA_SPECS
    Signal 2: MITRE tactics → MITRE_TACTIC_TO_CSF → CSF prefix → CSF_TO_HIPAA_SPECS
    Signal 3: behavioral booleans → BEHAVIOR_TO_HIPAA_SPEC (direct)
    """
    relevant_spec_codes   = set()
    relevant_cfr_sections = set()
    signal_log            = []

    cis_mapping = findings.get("cis_controls_mapping", {})
    ti          = findings.get("threat_intelligence",  {})
    ua          = findings.get("user_activity",        {})

    # Signal 1: CIS controls → NIST subcategories → CSF prefix → HIPAA specs
    for ctrl in cis_mapping.get("control_ids", []):
        for nist_id in CIS_TO_NIST_MAPPINGS.get(ctrl, []):
            csf_cat   = nist_id.rsplit("-", 1)[0] # "PR.AA"
            csf_exact = nist_id                            # "PR.AA-01"
            matched   = CSF_TO_HIPAA_SPECS.get(csf_exact, []) or CSF_TO_HIPAA_SPECS.get(csf_cat, [])
            if matched:
                relevant_spec_codes.update(matched)
                signal_log.append(f"{ctrl}→{nist_id}→{csf_cat}→{len(matched)} specs")

    # Signal 2: MITRE tactics → CSF → HIPAA specs
    for tactic in ti.get("mitre_attack_tactics", []):
        for csf_cat in MITRE_TACTIC_TO_CSF.get(tactic, []):
            matched = CSF_TO_HIPAA_SPECS.get(csf_cat, [])
            if matched:
                relevant_spec_codes.update(matched)
                signal_log.append(f"MITRE:{tactic}→{csf_cat}→{len(matched)} specs")

    # Signal 3: behavioral booleans → direct spec codes
    for field, spec_codes in BEHAVIOR_TO_HIPAA_SPEC.items():
        if ua.get(field):
            relevant_spec_codes.update(spec_codes)
            signal_log.append(f"behavior:{field}→{spec_codes}")

    # Resolve spec codes → parent CFR sections
    # Resolve spec codes → parent CFR sections
    for code in relevant_spec_codes:
        cfr = HIPAA_SPEC_REGISTRY.get(code, {}).get("cfr", "")
        m   = re.match(r"(164\.\d{3})", cfr)
        if m:
            relevant_cfr_sections.add(m.group(1))

    # ── Signal 4 (NEW): CFR section anchors extracted from investigation_query ──
    # This is the safety net when Signals 1-3 all produce nothing (e.g. empty
    # control_ids from LLM). The investigation_query is prompted to include
    # §164.XXX anchors — extract them directly.
    investigation_query = findings.get("_investigation_query", "")
    if not relevant_cfr_sections and investigation_query:
        for m in re.finditer(r"164\.\d{3}", investigation_query):
            relevant_cfr_sections.add(m.group(0))
            signal_log.append(f"query_anchor→{m.group(0)}")

    # ── Signal 5 (NEW): Broad fallback — always guarantee minimum HIPAA coverage ─
    # If still nothing after all signals, seed with the 3 most universal sections.
    if not relevant_cfr_sections:
        relevant_cfr_sections = {"164.308", "164.312"}
        signal_log.append("fallback_seed→164.308,164.312")

    return relevant_spec_codes, relevant_cfr_sections, signal_log

def retrieve_cis_controls_llm(
    embedder,
    reranker,
    findings:            dict,
    investigation_query: str,
    log_type:            str = "auto",
    density=None,
) -> list:
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  RAG RETRIEVAL  |  Log type: {log_type.upper()}")
    print(f"{sep}")

    conn = get_pg_connection()
    cur  = conn.cursor()

    _timings = {}
    _t_rag_start = time.perf_counter()

    # ── Stage 2a: per-control scoped retrieval ────────────────────────────────
    print("\nStage 2a — Per-control targeted retrieval (control-scoped)...")
    per_ctrl_queries = build_per_control_queries_from_llm(findings)
    mapped_controls  = [q[0] for q in per_ctrl_queries]
    print(f"  Controls mapped: {mapped_controls}")

    all_docs:  list = []
    all_metas: list = []
    seen_ids:  set  = set()
    doc_ctrl_query: dict = {}

    # Batch-embed all per-control queries in one encoder call
    ctrl_keys    = [q[0] for q in per_ctrl_queries]
    ctrl_queries = [q[1] for q in per_ctrl_queries]
    _t = time.perf_counter()
    if ctrl_queries:
        ctrl_vecs = embedder.embed(ctrl_queries)   # single batched encode
    else:
        ctrl_vecs = []
    _timings["2a_embed"] = time.perf_counter() - _t

    _t = time.perf_counter()
    for ctrl_key, ctrl_query, q_vec in zip(ctrl_keys, ctrl_queries, ctrl_vecs):
        # Deterministic: always filter by framework_id + control_id so cross-
        # framework leakage cannot push out guaranteed CIS slots.
        cur.execute(f"""
            SELECT id, document, control_id, safeguard_id, type
            FROM {PG_TABLE}
            WHERE framework_id = 'cis_v8'
              AND type IN ('safeguard', 'control_overview')
              AND control_id = %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
        """, (ctrl_key, q_vec, TOP_K_PER_CTRL))
        for doc_id, doc, ctrl_id, sfg_id, chunk_type in cur.fetchall():
            if doc_id not in seen_ids:
                seen_ids.add(doc_id)
                idx = len(all_docs)
                all_docs.append(doc)
                all_metas.append({
                    "framework_id":  "cis_v8",
                    "control_id":   ctrl_id,
                    "safeguard_id": sfg_id,
                    "type":         chunk_type,
                })
                doc_ctrl_query[idx] = ctrl_query
    _timings["2a_db_fetch"] = time.perf_counter() - _t

    print(f"  Candidates from per-control queries: {len(all_docs)}")
    print(f"  [timing] 2a_embed={_timings['2a_embed']:.4f}s  2a_db_fetch={_timings['2a_db_fetch']:.4f}s")

    # ── Stage 2b: unscoped sweeps — sequential CIS / NIST / HIPAA retrieval ──
    # Embeddings are batch-encoded (single encoder call); DB queries are sequential.
    print("Stage 2b — CIS + NIST + HIPAA sweep (batch embed, sequential DB)...")
    # Embed the shared query once; HIPAA query built after signal mapping below.
    _t = time.perf_counter()
    cq_vec = embedder.embed([investigation_query])[0]
    _timings["2b_embed_initial"] = time.perf_counter() - _t
    # hipaa_query_vec will be computed below after HIPAA query is assembled;
    # if no HIPAA enrichment is needed, cq_vec is reused as the fallback.

    _t = time.perf_counter()
    cur.execute(f"""
        SELECT id, document, control_id, safeguard_id, type
        FROM {PG_TABLE}
        WHERE framework_id = 'cis_v8'
          AND type IN ('safeguard', 'control_overview')
        ORDER BY embedding <=> %s::vector
        LIMIT %s;
    """, (cq_vec, TOP_K))

    for doc_id, doc, ctrl_id, sfg_id, chunk_type in cur.fetchall():
        if doc_id not in seen_ids:
            seen_ids.add(doc_id)
            idx = len(all_docs)
            all_docs.append(doc)
            all_metas.append({
                "framework_id":  "cis_v8",
                "control_id":    ctrl_id,
                "safeguard_id":  sfg_id,
                "type":          chunk_type,
            })
            m = re.search(r'Control (\d+)', ctrl_id) if ctrl_id else None
            ctrl_key = f"Control {m.group(1)}" if m else None
            doc_ctrl_query[idx] = (
                _CONTROL_SENTENCES.get(ctrl_key, investigation_query)
                if ctrl_key else investigation_query
            )
    _timings["2b_cis_unscoped_db"] = time.perf_counter() - _t
    print(f"  [timing] 2b_embed_initial={_timings['2b_embed_initial']:.4f}s  2b_cis_unscoped_db={_timings['2b_cis_unscoped_db']:.4f}s")

    # ── Resolve NIST IDs from mapped controls (SCF 2026.1 source) ────────────
    # CIS_TO_NIST_MAPPINGS is loaded from furix_det at startup (phase1_scf_ingest.py).
    relevant_nist_ids = set()
    for ctrl_id in mapped_controls:
        for nist_id in CIS_TO_NIST_MAPPINGS.get(ctrl_id, []):
            relevant_nist_ids.add(nist_id)
    print(f"  SCF-derived NIST IDs for {len(mapped_controls)} controls: {len(relevant_nist_ids)} unique IDs")

    # ── Build HIPAA signal mapping (needed before embedding HIPAA query) ──────
    findings["_investigation_query"] = investigation_query
    relevant_spec_codes, relevant_cfr_sections, hipaa_signal_log = \
        map_log_to_hipaa_specs(findings)
    findings.pop("_investigation_query", None)

    spec_names = [
        HIPAA_SPEC_REGISTRY[s]["name"]
        for s in list(relevant_spec_codes)[:8]
        if s in HIPAA_SPEC_REGISTRY
    ]
    # If investigation_query is a stub (fallback), build a richer HIPAA anchor
    # from the raw log signals directly so embedding lands in the right spec space.
    _query_is_stub = len(investigation_query.split()) < 20
    if _query_is_stub:
        density_context = " ".join([
            m.replace("\\", "").replace("(", "").replace(")", "")
            for m in (density.get("matched_threats", [])[:5] if density else [])
        ]) if "density" in dir() else ""
        ctrl_context = " ".join(mapped_controls[:6])
        hipaa_base = (
            f"Security incident involving {density_context}. "
            f"Relevant controls: {ctrl_context}. "
            f"HIPAA safeguards: {', '.join(spec_names[:5])}"
        ) if density_context or ctrl_context else investigation_query
    else:
        hipaa_base = investigation_query

    # Extract attack-signal terms from findings to anchor HIPAA embedding
    # toward detection/access specs rather than response/recovery specs
    _ti    = findings.get("threat_intelligence", {}) or {}
    _ua    = findings.get("user_activity", {})        or {}
    _sf    = findings.get("security_findings", {})    or {}

    _attack_signals = []
    _fired_spec_codes = []

    if _ua.get("privilege_escalation_detected"):
        _attack_signals.append("privilege escalation workforce access control authorization")
        _fired_spec_codes.extend(["AS-WS-AS", "AS-IAM-AA", "TS-AC-UUI"])
    if _ua.get("failed_logins"):
        _attack_signals.append(
            "authentication failure unique user identification login monitoring audit"
        )
        _fired_spec_codes.extend(["AS-SAT-LM", "TS-AC-UUI"])
    if _ua.get("account_creation_detected"):
        _attack_signals.append("workforce clearance authorization access management")
        _fired_spec_codes.extend(["AS-WS-TP", "AS-IAM-AEM"])
    if any("malware" in str(t).lower() or "c2" in str(t).lower()
           for t in _ti.get("mitre_attack_tactics", [])):
        _attack_signals.append(
            "malicious software protection audit controls system monitoring"
        )
        _fired_spec_codes.extend(["AS-SAT-PM", "TS-AUC"])
    if _ti.get("cve_ids", ["NAN"]) != ["NAN"]:
        _attack_signals.append(
            "vulnerability management security awareness training patch"
        )

    # Resolve fired spec codes to human-readable names for embedding richness
    _fired_spec_names = list(dict.fromkeys([
        HIPAA_SPEC_REGISTRY[s]["name"]
        for s in _fired_spec_codes
        if s in HIPAA_SPEC_REGISTRY
    ]))

    _attack_anchor = " ".join(_attack_signals)
    _primary = _sf.get("primary_finding") or ""

    # Build HIPAA query: attack signals first, then spec names, then general query
    # Order matters for embedding — lead with attack vocabulary, not response vocabulary
    hipaa_query = " ".join(filter(None, [
        _attack_anchor,
        f"HIPAA controls: {', '.join(_fired_spec_names[:5])}" if _fired_spec_names else "",
        f"related safeguards: {', '.join(spec_names[:4])}" if spec_names else "",
        _primary[:100] if _primary else "",
    ]))
    if not hipaa_query.strip():
        hipaa_query = hipaa_base

    # ── Batch-embed all three framework queries in ONE encoder call ────────────
    _t = time.perf_counter()
    embed_inputs = [investigation_query, investigation_query, hipaa_query]
    cis_nist_vec, nist_vec, hipaa_vec = embedder.embed(embed_inputs)
    cq_vec = cis_nist_vec  # alias for CIS unscoped + NIST scoped
    _timings["2b_embed_frameworks"] = time.perf_counter() - _t

# ── Execute CIS/NIST/HIPAA framework queries in parallel ─────────────────
    def _fetch_cis(vec):
        c = get_pg_connection(); cur_ = c.cursor()
        cur_.execute(f"""
            SELECT id, document, control_id, safeguard_id, type
            FROM {PG_TABLE}
            WHERE framework_id = 'cis_v8'
              AND type IN ('safeguard', 'control_overview')
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
        """, (vec, TOP_K))
        rows = cur_.fetchall(); cur_.close(); c.close()
        return ("cis", rows)

    def _fetch_nist(vec, id_list):
        if not id_list:
            return ("nist", [])
        c = get_pg_connection(); cur_ = c.cursor()
        cur_.execute(f"""
            SELECT id, document, control_id, safeguard_id, type
            FROM {PG_TABLE}
            WHERE framework_id = 'nist_csf'
              AND (node_id IN ({id_list}) OR safeguard_id IN ({id_list}) OR control_id IN ({id_list}))
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
        """, (vec, TOP_K))
        rows = cur_.fetchall(); cur_.close(); c.close()
        return ("nist", rows)

    def _fetch_hipaa(vec, section_list):
        c = get_pg_connection(); cur_ = c.cursor()
        if section_list:
            cur_.execute(f"""
                SELECT id, document, control_id, safeguard_id, type
                FROM {PG_TABLE}
                WHERE framework_id = 'hipaa_security_rule'
                  AND control_id IN ({section_list})
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
            """, (vec, TOP_K))
        else:
            cur_.execute(f"""
                SELECT id, document, control_id, safeguard_id, type
                FROM {PG_TABLE}
                WHERE framework_id = 'hipaa_security_rule'
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
            """, (vec, HIPAA_GUARANTEED * 3))
        rows = cur_.fetchall(); cur_.close(); c.close()
        return ("hipaa", rows)

    nist_id_list_str  = ", ".join(f"'{n}'" for n in sorted(relevant_nist_ids)) if relevant_nist_ids else ""
    hipaa_section_str = ", ".join(f"'{s}'" for s in sorted(relevant_cfr_sections)) if relevant_cfr_sections else ""

    _t = time.perf_counter()
    nist_rows = []; hipaa_rows = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(_fetch_cis,   cis_nist_vec):              "cis",
            pool.submit(_fetch_nist,  nist_vec, nist_id_list_str): "nist",
            pool.submit(_fetch_hipaa, hipaa_vec, hipaa_section_str): "hipaa",
        }
        for future in as_completed(futures):
            label, rows = future.result()
            if label == "cis":
                for doc_id, doc, ctrl_id, sfg_id, chunk_type in rows:
                    if doc_id not in seen_ids:
                        seen_ids.add(doc_id)
                        idx = len(all_docs)
                        all_docs.append(doc)
                        all_metas.append({"framework_id": "cis_v8", "control_id": ctrl_id, "safeguard_id": sfg_id, "type": chunk_type})
                        m = re.search(r'Control (\d+)', ctrl_id) if ctrl_id else None
                        ctrl_key = f"Control {m.group(1)}" if m else None
                        doc_ctrl_query[idx] = (_CONTROL_SENTENCES.get(ctrl_key, investigation_query) if ctrl_key else investigation_query)
            elif label == "nist":
                nist_rows = rows
            elif label == "hipaa":
                hipaa_rows = rows
    _timings["2b_parallel_db"] = time.perf_counter() - _t
    print(f"  [timing] 2b_embed_frameworks={_timings['2b_embed_frameworks']:.4f}s  2b_parallel_db={_timings['2b_parallel_db']:.4f}s")

    # ── Ingest NIST results ───────────────────────────────────────────────────
    nist_added = 0
    for doc_id, doc, ctrl_id, sfg_id, chunk_type in nist_rows:
        if doc_id not in seen_ids:
            seen_ids.add(doc_id)
            idx = len(all_docs)
            all_docs.append(doc)
            all_metas.append({
                "framework_id": "nist_csf",
                "control_id":   ctrl_id or "",
                "safeguard_id": sfg_id  or "",
                "type":         chunk_type or "",
            })
            sfg_prefix = (sfg_id or "").rsplit("-", 1)[0]
            doc_ctrl_query[idx] = (
                _NIST_CATEGORY_SENTENCES.get(sfg_id)
                or _NIST_CATEGORY_SENTENCES.get(sfg_prefix)
                or _NIST_CATEGORY_SENTENCES.get(ctrl_id)
                or investigation_query
            )
            nist_added += 1

    # ── Ingest HIPAA results ──────────────────────────────────────────────────
    hipaa_added = 0
    for doc_id, doc, ctrl_id, sfg_id, chunk_type in hipaa_rows:
        if doc_id not in seen_ids:
            seen_ids.add(doc_id)
            idx = len(all_docs)
            all_docs.append(doc)
            all_metas.append({
                "framework_id": "hipaa_security_rule",
                "control_id":   ctrl_id or "",
                "safeguard_id": sfg_id  or "",
                "type":         chunk_type or "",
            })
            doc_ctrl_query[idx] = hipaa_query
            hipaa_added += 1

    cis_count = len(all_docs) - nist_added - hipaa_added
    print(f"  CIS sweep   : {cis_count} candidates")
    print(f"  NIST sweep  : {nist_added} candidates (IDs: {len(relevant_nist_ids)})")
    print(f"  HIPAA sweep : {hipaa_added} candidates (CFR: {sorted(relevant_cfr_sections)})")
    print(f"  HIPAA signals: {len(hipaa_signal_log)} fired")

    # ── Stage 2c: Quality filter + safeguard dedup ────────────────────────────
    print("Stage 2c — Quality filter + safeguard-level deduplication...")
    _t = time.perf_counter()
    dedup_docs:    list = []
    dedup_metas:   list = []
    dedup_queries: list = []
    seen_sfg_ids:  dict = {}
    dropped_quality = 0

    for orig_idx, (doc, meta) in enumerate(zip(all_docs, all_metas)):
        if not _is_quality_chunk(doc, meta):
            dropped_quality += 1
            continue
        sfg_id  = meta.get("safeguard_id", "")
        ctrl_id = meta.get("control_id",   "")
        if sfg_id:
            if sfg_id not in seen_sfg_ids:
                seen_sfg_ids[sfg_id] = len(dedup_docs)
                dedup_docs.append(doc)
                dedup_metas.append(meta)
                dedup_queries.append(doc_ctrl_query.get(orig_idx, investigation_query))
        else:
            combo_key = f"{ctrl_id}::{meta.get('type', '')}"
            if combo_key not in seen_sfg_ids:
                seen_sfg_ids[combo_key] = len(dedup_docs)
                dedup_docs.append(doc)
                dedup_metas.append(meta)
                dedup_queries.append(doc_ctrl_query.get(orig_idx, investigation_query))
    _timings["2c_quality_filter_dedup"] = time.perf_counter() - _t

    print(f"  Dropped by quality filter: {dropped_quality}")
    print(f"  Candidates after dedup:    {len(dedup_docs)}  (was {len(all_docs)})")
    print(f"  [timing] 2c_quality_filter_dedup={_timings['2c_quality_filter_dedup']:.4f}s")

    # ── Zero-result RAG recovery ──────────────────────────────────────────────
    # If quality filter + dedup emptied the pool, fall back to a broad unfiltered
    # sweep so Stage 3 always receives at least some candidates.
    if not dedup_docs:
        print("  [RECOVERY] Zero candidates after dedup — running broad fallback sweep...")
        recovery_vec = embedder.embed([investigation_query])[0]
        try:
            cur.execute(f"""
                SELECT id, document, framework_id, control_id, safeguard_id, type
                FROM {PG_TABLE}
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
            """, (recovery_vec, TOP_K_RERANK * 2))
        except Exception as _rec_err:
            print(f"  [RECOVERY] DB query failed: {_rec_err}")
            cur.close(); conn.close()
            return [], _timings
        for doc_id, doc, fw_id, ctrl_id, sfg_id, chunk_type in cur.fetchall():
            if doc_id not in seen_ids:
                seen_ids.add(doc_id)
                dedup_docs.append(doc)
                dedup_metas.append({
                    "framework_id":  fw_id or "cis_v8",
                    "control_id":    ctrl_id or "",
                    "safeguard_id":  sfg_id  or "",
                    "type":          chunk_type or "",
                })
                dedup_queries.append(investigation_query)
        print(f"  [RECOVERY] Fallback retrieved {len(dedup_docs)} candidates")

    # ── Stage 2c.5: Pre-rerank cap — limit cross-encoder input size ───────────
    # Cross-encoder cost scales linearly with candidates. Cap at 2×TOP_K_RERANK
    # to bound rerank time without losing coverage — the best chunks are already
    # near the top from pgvector cosine ordering.
    _t = time.perf_counter()
    MAX_RERANK_CANDIDATES = TOP_K_RERANK + 10
    if len(dedup_docs) > MAX_RERANK_CANDIDATES:
        # Framework-aware cap: guarantee minimum slots per framework before truncating
        FRAMEWORK_FLOOR = {
            "cis_v8":               CIS_GUARANTEED,
            "nist_csf":             NIST_GUARANTEED,
            "hipaa_security_rule":  HIPAA_GUARANTEED,
        }
        capped_docs, capped_metas, capped_queries = [], [], []
        fw_counts = {"cis_v8": 0, "nist_csf": 0, "hipaa_security_rule": 0}

        # Pass 1: fill guaranteed floor slots per framework
        for doc, meta, query in zip(dedup_docs, dedup_metas, dedup_queries):
            fw = meta.get("framework_id", "cis_v8")
            if fw_counts.get(fw, 0) < FRAMEWORK_FLOOR.get(fw, 0):
                capped_docs.append(doc)
                capped_metas.append(meta)
                capped_queries.append(query)
                fw_counts[fw] = fw_counts.get(fw, 0) + 1

        guaranteed_indices = set(range(len(capped_docs)))
        seen_cap = set(id(d) for d in capped_docs)  # keep for the loop below

        remaining_budget = MAX_RERANK_CANDIDATES - len(capped_docs)
        for doc, meta, query in zip(dedup_docs, dedup_metas, dedup_queries):
            if remaining_budget <= 0:
                break
            if id(doc) not in seen_cap:
                capped_docs.append(doc)
                capped_metas.append(meta)
                capped_queries.append(query)
                seen_cap.add(id(doc))
                remaining_budget -= 1

        dedup_docs    = capped_docs
        dedup_metas   = capped_metas
        dedup_queries = capped_queries
        print(f"  Pre-rerank cap applied:    {len(dedup_docs)} candidates "
            f"(CIS≥{fw_counts['cis_v8']} NIST≥{fw_counts['nist_csf']} "
            f"HIPAA≥{fw_counts['hipaa_security_rule']})")
    _timings["2c5_prerank_cap"] = time.perf_counter() - _t
    print(f"  [timing] 2c5_prerank_cap={_timings['2c5_prerank_cap']:.4f}s")

    # ── Stage 2d: Graph expansion ─────────────────────────────────────────────
    print("Stage 2d — Graph expansion (NIST mappings + related controls)...")
    _t = time.perf_counter()
    pool_ctrl_ids = list({
        m.get("control_id", "")
        for m in dedup_metas
        if m.get("control_id", "")
        and m.get("framework_id", "cis_v8") == "cis_v8"   # ← add this filter
    })
    graph_expansion = graph_expand_controls(pool_ctrl_ids)
    _timings["2d_graph_expansion_db"] = time.perf_counter() - _t
    total_nist    = sum(len(v["nist_mappings"])    for v in graph_expansion.values())
    total_related = sum(len(v["related_controls"]) for v in graph_expansion.values())
    nist_chunk_count = sum(1 for m in dedup_metas if m.get("framework_id") == "nist_csf")
    cis_chunk_count  = sum(1 for m in dedup_metas if m.get("framework_id") == "cis_v8")
    print(f"  Controls expanded: {len(pool_ctrl_ids)}")
    print(f"  NIST mappings found:    {total_nist}")
    print(f"  Related CIS controls:   {total_related}")
    print(f"  CIS chunks in pool:  {cis_chunk_count}")
    print(f"  NIST chunks in pool: {nist_chunk_count}")
    print(f"  [timing] 2d_graph_expansion_db={_timings['2d_graph_expansion_db']:.4f}s")

    # ── Stage 3: Rerank with NIST guarantee ───────────────────────────────────
    print("Stage 3 — Rerank + coverage guarantee + NIST slot guarantee...")
    _t = time.perf_counter()
    final, guaranteed_docs = _stage3_rerank_with_nist_guarantee(
        dedup_docs, dedup_metas, dedup_queries,
        investigation_query, mapped_controls, graph_expansion,
        reranker,
    )
    _timings["3_rerank_total"] = time.perf_counter() - _t
    print(f"  [timing] 3_rerank_total={_timings['3_rerank_total']:.4f}s")

    # ── Display results ───────────────────────────────────────────────────────
    print(f"\n{sep}")
    print("  RESULTS — CIS Controls v8.1 + NIST CSF 2.0 + HIPAA Security Rule Remediation")
    print(f"{sep}")

    for rank, (score, doc, meta) in enumerate(final, 1):
        control_id   = meta.get("control_id",   "General")
        safeguard_id = meta.get("safeguard_id", "")
        chunk_type   = meta.get("type", "")
        nist_maps    = meta.get("nist_mappings",    [])
        related_ctrl = meta.get("related_controls", [])

        label   = control_id + (f"  |  Safeguard {safeguard_id}" if safeguard_id else "")
        cov_tag = " [coverage]" if id(doc) in guaranteed_docs else ""
        print(f"\n[{rank}] {label}  (rerank score: {round(float(score), 4)})  [{chunk_type}]{cov_tag}")
        print("    " + "─" * 64)
        preview = doc[:600].replace("\n", " ").strip()
        if len(doc) > 600:
            preview += "..."
        print(f"    {preview}")
        if nist_maps:
            print(f"    ── NIST CSF 2.0 Mappings {'─' * 38}")
            for entry in nist_maps:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    print(f"       {entry[0]}  [{entry[1]}]")
                else:
                    print(f"       {entry}")
        if related_ctrl:
            print(f"    ── Related CIS Controls {'─' * 39}")
            print(f"       {', '.join(related_ctrl)}")

    # _timings is returned (not printed here) — run_full_pipeline() in pipeline.py
    # folds it into the single consolidated compliance/runtime summary printed
    # once per log, instead of duplicating a breakdown table here as well.
    _timings["total_rag_retrieval"] = time.perf_counter() - _t_rag_start

    print(f"\n{sep}")
    print("  Pipeline complete: LLM → validate → quality-filter → dedup → graph-expand → rerank")
    print(f"{sep}\n")
    # Close the main connection on the success path too (the recovery path at the
    # top already closes it). Without this the API server leaked one PG connection
    # per ingested log and would exhaust the pool. Exceptions between open and here
    # propagate to run_full_pipeline's Phase-2 handler; see the finally-guard note.
    try:
        cur.close()
        conn.close()
    except Exception:
        pass
    return final, _timings

# %%