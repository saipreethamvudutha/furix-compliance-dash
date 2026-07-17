"""
setup_ingestion.py
==================
Run ONCE to build the entire data layer. Never imported by other modules.

    python setup_ingestion.py

What it builds:
  1. Apache AGE compliance_graph — Framework, Control, Safeguard, NISTCategory
     nodes and HAS_SAFEGUARD, MAPS_TO, RELATED_TO edges.
     MAPS_TO edges use CIS_TO_NIST_MAPPINGS from furix_det (SCF 2026.1).
  2. pgvector compliance_chunks table — SecureBERT-768 embeddings of CIS v8.1,
     NIST CSF 2.0, and HIPAA Security Rule text chunks.

Safe to re-run — both the graph and the chunks table are dropped and
recreated cleanly on each run.

This file is NEVER imported by pipeline.py, retrieval_engine.py,
or any other module. Importing it would re-run all ingestion.
embedder and reranker come from models.py.
HIPAA lookup dicts come from hipaa_data.py.
"""

import os, re, json, warnings
import pdfplumber
import psycopg2
from psycopg2.extras import execute_values

warnings.filterwarnings("ignore")

from config import (
    PDF_PATH, NIST_DATA_PATH, HIPAA_JSON_PATH,
    PG_TABLE, EMBED_DIM, AGE_GRAPH_NAME,
    CHUNK_SIZE, CHUNK_OVERLAP,
)
from db_connections import (
    get_pg_connection, get_age_connection, get_age_read_connection,
    CIS_TO_NIST_MAPPINGS, HIPAA_TO_NIST_MAPPINGS,
)
from hipaa_data import (
    hipaa_json,
    CSF_TO_HIPAA_SPECS, HIPAA_SPEC_REGISTRY,
    MITRE_TACTIC_TO_CSF, BEHAVIOR_TO_HIPAA_SPEC,
)

def setup_age_graph():
    """
    Creates the compliance_graph in Apache AGE.
    Idempotent — safe to re-run; drops and recreates cleanly.
    """
    conn = get_age_connection()
    cur  = conn.cursor()

    # Drop existing graph if present (clean slate)
    try:
        cur.execute(f"SELECT drop_graph('{AGE_GRAPH_NAME}', true);")
        print(f"  Dropped existing graph: {AGE_GRAPH_NAME}")
    except Exception:
        pass  # graph didn't exist yet — fine

    # Create fresh graph
    cur.execute(f"SELECT create_graph('{AGE_GRAPH_NAME}');")
    print(f"  Created graph: {AGE_GRAPH_NAME}")

    # Create node labels
    for label in ["Framework", "Control", "Safeguard", "NISTCategory"]:
        cur.execute(f"SELECT create_vlabel('{AGE_GRAPH_NAME}', '{label}');")
        print(f"  Created node label: {label}")

    # Create edge labels
    for label in ["HAS_SAFEGUARD", "MAPS_TO", "RELATED_TO"]:
        cur.execute(f"SELECT create_elabel('{AGE_GRAPH_NAME}', '{label}');")
        print(f"  Created edge label: {label}")

    cur.close()
    conn.close()
    print("✅ AGE graph schema ready")


def run_cypher(conn, query, params=None):
    """
    Helper to execute a Cypher query via psycopg2.
    AGE returns results as agtype — we cast to text for easy parsing.
    """
    cur = conn.cursor()
    try:
        cur.execute(query)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Cypher ERROR] {e}")
        print(f"  Query: {query[:200]}")
    finally:
        cur.close()


def cypher(graph, query):
    """Wraps a Cypher query in the ag_catalog.cypher() call."""
    return f"SELECT * FROM ag_catalog.cypher('{graph}', $$ {query} $$) AS (result agtype);"


def ingest_cis_to_graph():
    conn = get_age_connection()
    print("\nIngesting CIS Controls into AGE graph...")

    # ── 1. Framework node ─────────────────────────────────────────────────────
    run_cypher(conn, cypher(AGE_GRAPH_NAME,
        """CREATE (:Framework {
            id:      'cis_v8',
            name:    'CIS Controls',
            version: 'v8.1.2'
        })"""
    ))
    print("  ✓ Framework node created")

    # ── 2. Control nodes (Control 1–18) ───────────────────────────────────────
    control_names = {
        "Control 1":  "Inventory and Control of Enterprise Assets",
        "Control 2":  "Inventory and Control of Software Assets",
        "Control 3":  "Data Protection",
        "Control 4":  "Secure Configuration of Enterprise Assets and Software",
        "Control 5":  "Account Management",
        "Control 6":  "Access Control Management",
        "Control 7":  "Continuous Vulnerability Management",
        "Control 8":  "Audit Log Management",
        "Control 9":  "Email and Web Browser Protections",
        "Control 10": "Malware Defenses",
        "Control 11": "Data Recovery",
        "Control 12": "Network Infrastructure Management",
        "Control 13": "Network Monitoring and Defense",
        "Control 14": "Security Awareness and Skills Training",
        "Control 15": "Service Provider Management",
        "Control 16": "Application Software Security",
        "Control 17": "Incident Response Management",
        "Control 18": "Penetration Testing",
    }

    for ctrl_id, ctrl_name in control_names.items():
        ctrl_num = ctrl_id.split(" ")[1]
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:Control {{
                id:           '{ctrl_id}',
                name:         '{ctrl_name}',
                control_num:  '{ctrl_num}',
                framework_id: 'cis_v8'
            }})"""
        ))
    print(f"  ✓ {len(control_names)} Control nodes created")

    # ── 3. Safeguard nodes + HAS_SAFEGUARD edges ──────────────────────────────
    # CORRECTED counts from CIS v8.1 spec
    safeguard_counts = {
        "Control 1": 5,  "Control 2": 7,  "Control 3": 14,
        "Control 4": 12, "Control 5": 6,  "Control 6": 8,
        "Control 7": 7,  "Control 8": 12, "Control 9": 7,
        "Control 10": 7, "Control 11": 5, "Control 12": 8,
        "Control 13": 11,"Control 14": 9, "Control 15": 7,
        "Control 16": 14,"Control 17": 9, "Control 18": 5,
    }
    # Verify total = 153
    # Replace assert with:
    total_sfg = sum(safeguard_counts.values())
    if total_sfg != 153:
        print(f"[WARN] Expected 153 safeguards, got {total_sfg} — check spec version")

    sfg_total = 0
    for ctrl_id, count in safeguard_counts.items():
        ctrl_num = ctrl_id.split(" ")[1]
        for i in range(1, count + 1):
            sfg_id = f"{ctrl_num}.{i}"
            run_cypher(conn, cypher(AGE_GRAPH_NAME,
                f"""CREATE (:Safeguard {{
                    id:           '{sfg_id}',
                    control_id:   '{ctrl_id}',
                    framework_id: 'cis_v8'
                }})"""
            ))
            run_cypher(conn, cypher(AGE_GRAPH_NAME,
                f"""MATCH (c:Control   {{id: '{ctrl_id}'}}),
                          (s:Safeguard {{id: '{sfg_id}'}})
                    CREATE (c)-[:HAS_SAFEGUARD]->(s)"""
            ))
            sfg_total += 1

    print(f"  ✓ {sfg_total} Safeguard nodes + HAS_SAFEGUARD edges created")

    # ── 4. RELATED_TO edges (known CIS control relationships) ─────────────────
    # NOTE: NO MAPS_TO edges here — those are created in ingest_nist_to_graph()
    related_pairs = [
        ("Control 1",  "Control 2"),
        ("Control 5",  "Control 6"),
        ("Control 6",  "Control 12"),
        ("Control 7",  "Control 4"),
        ("Control 8",  "Control 13"),
        ("Control 10", "Control 13"),
        ("Control 12", "Control 13"),
        ("Control 3",  "Control 11"),
        ("Control 14", "Control 9"),
        ("Control 15", "Control 6"),
        ("Control 16", "Control 7"),
        ("Control 17", "Control 13"),
    ]
    for src, dst in related_pairs:
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""MATCH (a:Control {{id: '{src}'}}),
                      (b:Control {{id: '{dst}'}})
                CREATE (a)-[:RELATED_TO]->(b)"""
        ))
    print(f"  ✓ {len(related_pairs)} RELATED_TO edges created")

    conn.close()
    print("✅ CIS graph ingestion complete")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8c — CIS PDF extraction + boundary-aware smart_chunk
# ─────────────────────────────────────────────────────────────────────────────

def extract_pdf_text(path: str) -> str:
    """Extract full text from PDF using pdfplumber, page by page."""
    full_text = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)
    return "\n".join(full_text)


# ── Patterns ──────────────────────────────────────────────────────────────────
CIS_CONTROL_RE   = re.compile(r"^CONTROL\s+(\d+)\s*$", re.MULTILINE | re.IGNORECASE)
CIS_SAFEGUARD_RE = re.compile(r"^Safeguard\s+(\d+)\.(\d+)[:\s]", re.MULTILINE)


def _split_into_sections(text: str) -> list:
    """
    Splits CIS full text into boundary-aligned sections.
    Each section = { start_pos, end_pos, control_id, safeguard_id, type }
    Boundaries are: CONTROL N header, Safeguard N.M header.
    """
    boundaries = []

    # Collect all CONTROL boundaries
    for m in CIS_CONTROL_RE.finditer(text):
        boundaries.append({
            "pos":         m.start(),
            "control_id":  f"Control {m.group(1)}",
            "safeguard_id": "",
            "type":        "control_overview",
        })

    # Collect all Safeguard boundaries
    for m in CIS_SAFEGUARD_RE.finditer(text):
        ctrl_num = m.group(1)
        sfg_num  = m.group(2)
        boundaries.append({
            "pos":          m.start(),
            "control_id":   f"Control {ctrl_num}",
            "safeguard_id": f"{ctrl_num}.{sfg_num}",
            "type":         "safeguard",
        })

    # Sort all boundaries by position
    boundaries.sort(key=lambda x: x["pos"])

    # Build sections between consecutive boundaries
    sections = []
    for idx, b in enumerate(boundaries):
        end_pos = boundaries[idx + 1]["pos"] if idx + 1 < len(boundaries) else len(text)
        section_text = text[b["pos"]: end_pos].strip()
        if len(section_text) > 80:
            sections.append({
                "text":         section_text,
                "control_id":   b["control_id"],
                "safeguard_id": b["safeguard_id"],
                "type":         b["type"],
            })

    return sections


def _sliding_chunks(text: str, size: int, overlap: int) -> list:
    """
    Sliding window chunker used by smart_chunk_nist().
    Returns list of text pieces of max `size` chars with `overlap`.
    """
    pieces = []
    start  = 0
    while start < len(text):
        end   = min(start + size, len(text))
        piece = text[start:end].strip()
        if len(piece) > 50:
            pieces.append(piece)
        start += size - overlap
    return pieces


def smart_chunk(text: str, framework_id: str = "cis_v8") -> list:
    """
    Original CIS boundary-aware chunker — now accepts framework_id parameter.
    Each chunk gets framework_id injected into its metadata.
    """
    chunks = []
    boundary_pattern = re.compile(
        r"(?=CONTROL\s+\d+|Safeguard\s+\d+\.\d+|"
        r"Why is this Control critical\?|Procedures and tools)"
    )
    sections = [s for s in boundary_pattern.split(text) if len(s.strip()) > 80]

    for section in sections:
        control_m   = re.search(r"CONTROL\s+(\d+)", section)
        safeguard_m = re.search(
            r"Safeguard\s+(\d+\.\d+)|^(\d+\.\d+)\s*[:\-–]",
            section, re.MULTILINE
        )
        parent_safeguard_id = (
            safeguard_m.group(1) or safeguard_m.group(2)
        ) if safeguard_m else ""

        if parent_safeguard_id:
            ctrl_num          = parent_safeguard_id.split(".")[0]
            parent_control_id = f"Control {ctrl_num}"
        elif control_m:
            parent_control_id = f"Control {control_m.group(1)}"
        else:
            parent_control_id = "General"

        parent_type = (
            "safeguard"        if parent_safeguard_id else
            "control_overview" if control_m else
            "general"
        )

        if len(section) <= CHUNK_SIZE:
            chunks.append({
                "content":  section.strip(),
                "metadata": {
                    "framework_id": framework_id,
                    "control_id":   parent_control_id,
                    "safeguard_id": parent_safeguard_id,
                    "type":         parent_type,
                    "node_id":      parent_safeguard_id or parent_control_id,
                },
            })
        else:
            start = 0
            while start < len(section):
                end     = min(start + CHUNK_SIZE, len(section))
                content = section[start:end].strip()
                if len(content) > 50:
                    w_ctrl_m = re.search(r"CONTROL\s+(\d+)", content)
                    w_sfg_m  = re.search(
                        r"Safeguard\s+(\d+\.\d+)|^(\d+\.\d+)\s*[:\-–]",
                        content, re.MULTILINE
                    )
                    sfg_id = (
                        w_sfg_m.group(1) or w_sfg_m.group(2)
                    ) if w_sfg_m else parent_safeguard_id

                    if sfg_id:
                        ctrl_num = sfg_id.split(".")[0]
                        ctrl_id  = f"Control {ctrl_num}"
                    elif w_ctrl_m:
                        ctrl_id  = f"Control {w_ctrl_m.group(1)}"
                    else:
                        ctrl_id  = parent_control_id

                    c_type = (
                        "safeguard"        if sfg_id else
                        "control_overview" if ctrl_id != "General" else
                        "general"
                    )
                    chunks.append({
                        "content":  content,
                        "metadata": {
                            "framework_id": framework_id,
                            "control_id":   ctrl_id,
                            "safeguard_id": sfg_id,
                            "type":         c_type,
                            "node_id":      sfg_id or ctrl_id,
                        },
                    })
                start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


# ── Run extraction ────────────────────────────────────────────────────────────
def smart_chunk_hipaa(hipaa_json_data: dict) -> tuple:
    """
    Builds HIPAA chunks from structured JSON instead of PDF.

    Each chunk = one HIPAA implementation spec (leaf node).
    content   = spec name + parent standard name + CSF categories (clean ops-vocab)
    metadata  = cfr, spec code, csf list, ctl list, designation, proposed_2026 flag

    Returns (chunks, 0) — second value kept for compatibility with ingestion cell.
    """
    chunks = []

    for category in hipaa_json_data["safeguard_categories"]:
        cat_name = category["category"]   # e.g. "Administrative Safeguards"
        cfr_parent = category["cfr"]      # e.g. "164.308"

        for standard in category["standards"]:
            std_name = standard["name"]
            std_cfr  = standard["cfr"]
            std_csf  = standard.get("csf", [])
            std_ctl  = standard.get("ctl", [])

            # ── Chunk for the standard itself (if no specs, or as parent) ────
            if not standard.get("specs"):
                csf_labels = ", ".join(std_csf)
                content = (
                    f"HIPAA {cat_name} — {std_name}. "
                    f"CFR {std_cfr}. "
                    f"Security domains: {csf_labels}."
                )
                chunks.append({
                    "content": content,
                    "metadata": {
                        "framework_id": "hipaa_security_rule",
                        "control_id":   cfr_parent,
                        "safeguard_id": standard["code"],
                        "type":         "standard",
                        "node_id":      standard["code"],
                        "category":     cat_name,
                        "csf":          std_csf,
                        "ctl":          std_ctl,
                        "designation":  standard.get("designation", ""),
                    },
                })

            # ── Chunk for each implementation spec ───────────────────────────
            for spec in standard.get("specs", []):
                csf_labels  = ", ".join(spec.get("csf", []))
                ctl_labels  = ", ".join(spec.get("ctl", []))
                designation = spec.get("designation", "")
                proposed    = spec.get("proposed_2026", "")
                proposed_note = " (proposed Required under 2026 update)" if proposed == "R" else ""

                content = (
                    f"HIPAA {cat_name} — {std_name}: {spec['name']}. "
                    f"CFR {spec['cfr']}. "
                    f"Designation: {'Required' if designation == 'R' else 'Addressable'}"
                    f"{proposed_note}. "
                    f"Security domains: {csf_labels}. "
                    f"Related controls: {ctl_labels}."
                )
                chunks.append({
                    "content": content,
                    "metadata": {
                        "framework_id": "hipaa_security_rule",
                        "control_id":   cfr_parent,
                        "safeguard_id": spec["code"],
                        "type":         "implementation_spec",
                        "node_id":      spec["code"],
                        "category":     cat_name,
                        "csf":          spec.get("csf", []),
                        "ctl":          spec.get("ctl", []),
                        "designation":  designation,
                        "proposed_2026": proposed,
                        "parent_code":  standard["code"],
                    },
                })

    return chunks, 0   # 0 = no preamble skipped (kept for ingestion cell compat)
NIST_FUNC_RE    = re.compile(
    r"^(GOVERN|IDENTIFY|PROTECT|DETECT|RESPOND|RECOVER)\s*\(([A-Z]{2})\)",
    re.MULTILINE
)
NIST_CAT_RE     = re.compile(
    r"^[•\-\s]*([A-Z]{2}\.[A-Z]{2})\s*\(([^)]+)\)\s*:",
    re.MULTILINE
)
NIST_SUBCAT_RE  = re.compile(
    r"^[o\s]*([A-Z]{2}\.[A-Z]{2}-\d{2})\s*:",
    re.MULTILINE
)


def _split_nist_into_sections(text: str) -> list:
    """
    Splits NIST CSF 2.0 Appendix A into boundary-aligned sections.
    Hierarchy: Function → Category → Subcategory
    Only processes from 'Appendix A. CSF Core' onward.
    """
    # Find Appendix A start — that's where the actual CSF Core content is
    app_start = text.find("Appendix A. CSF Core")
    if app_start == -1:
        app_start = 0
    core_text = text[app_start:]

    boundaries = []

    # Function boundaries
    for m in NIST_FUNC_RE.finditer(core_text):
        boundaries.append({
            "pos":          m.start(),
            "function":     m.group(1),
            "function_id":  m.group(2),
            "category_id":  "",
            "subcat_id":    "",
            "type":         "function_overview",
        })

    # Category boundaries  e.g. "• Organizational Context (GV.OC):"
    for m in NIST_CAT_RE.finditer(core_text):
        cat_id = m.group(1)                      # e.g. "GV.OC"
        func_id = cat_id.split(".")[0]           # e.g. "GV"
        boundaries.append({
            "pos":          m.start(),
            "function":     func_id,
            "function_id":  func_id,
            "category_id":  cat_id,
            "subcat_id":    "",
            "type":         "category",
        })

    # Subcategory boundaries  e.g. "o GV.OC-01:"
    for m in NIST_SUBCAT_RE.finditer(core_text):
        subcat_id = m.group(1)                   # e.g. "GV.OC-01"
        cat_id    = subcat_id.rsplit("-", 1)[0]  # e.g. "GV.OC"
        func_id   = cat_id.split(".")[0]         # e.g. "GV"
        boundaries.append({
            "pos":          m.start(),
            "function":     func_id,
            "function_id":  func_id,
            "category_id":  cat_id,
            "subcat_id":    subcat_id,
            "type":         "subcategory",
        })

    # Sort by position
    boundaries.sort(key=lambda x: x["pos"])

    # Build sections between consecutive boundaries
    sections = []
    for idx, b in enumerate(boundaries):
        end_pos = boundaries[idx + 1]["pos"] if idx + 1 < len(boundaries) else len(core_text)
        section_text = core_text[b["pos"]: end_pos].strip()
        if len(section_text) > 60:
            sections.append({
                "text":         section_text,
                "function_id":  b["function_id"],
                "category_id":  b["category_id"],
                "subcat_id":    b["subcat_id"],
                "type":         b["type"],
            })

    return sections


def smart_chunk_nist(full_text: str) -> list:
    """
    Boundary-aware chunker for NIST CSF 2.0 PDF.
    Each chunk tagged with function, category, subcategory IDs.
    node_id = subcategory_id if exists, else category_id, else function_id.
    control_id field = category_id  (mirrors CIS control_id role)
    safeguard_id field = subcat_id  (mirrors CIS safeguard_id role)
    """
    sections = _split_nist_into_sections(full_text)
    chunks   = []

    for sec in sections:
        node_id = (
            sec["subcat_id"]   if sec["subcat_id"]   else
            sec["category_id"] if sec["category_id"] else
            sec["function_id"]
        )

        for piece in _sliding_chunks(sec["text"], CHUNK_SIZE, CHUNK_OVERLAP):
            chunks.append({
                "content":  piece,
                "metadata": {
                    "framework_id": "nist_csf",
                    "control_id":   sec["category_id"],
                    "safeguard_id": sec["subcat_id"],
                    "type":         sec["type"],
                    "node_id":      node_id,
                },
            })

    return chunks


# ── Run extraction ────────────────────────────────────────────────────────────
def setup_collection_multiframework(embedder) -> dict:
    """
    Ingests CIS v8.1 + NIST CSF 2.0 + HIPAA Security Rule into compliance_chunks.
    Returns dict: { "cis_v8": N, "nist_csf": N, "hipaa_security_rule": N, "total": N }
    """
    print("\n" + "=" * 72)
    print("  MULTI-FRAMEWORK INGESTION  (CIS + NIST + HIPAA)")
    print("=" * 72)

    # ── Step 1: Create extension ──────────────────────────────────────────────
    conn = get_pg_connection(register=False)
    cur  = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    conn.commit()
    cur.close(); conn.close()

    # ── Step 2: Create table ──────────────────────────────────────────────────
    conn = get_pg_connection(register=True)
    cur  = conn.cursor()
    cur.execute(f"DROP TABLE IF EXISTS {PG_TABLE};")
    cur.execute(f"""
        CREATE TABLE {PG_TABLE} (
            id           TEXT PRIMARY KEY,
            framework_id TEXT,
            document     TEXT,
            node_id      TEXT,
            control_id   TEXT,
            safeguard_id TEXT,
            type         TEXT,
            embedding    vector({EMBED_DIM})
        );
    """)
    conn.commit()
    print(f"Created table: '{PG_TABLE}' (CIS + NIST + HIPAA schema)")

    counts = {}
    BATCH  = 32

    # ── Step 3: Ingest CIS v8.1 ───────────────────────────────────────────────
    print(f"\n[1/3] CIS Controls v8.1 — reading PDF...")
    cis_text   = extract_pdf_text(PDF_PATH)
    cis_chunks = smart_chunk(cis_text, framework_id="cis_v8")
    print(f"  Extracted {len(cis_text):,} chars → {len(cis_chunks)} chunks")

    print(f"  Embedding & inserting {len(cis_chunks)} CIS chunks...")
    for i in range(0, len(cis_chunks), BATCH):
        batch = cis_chunks[i: i + BATCH]
        texts = [c["content"] for c in batch]
        embs  = embedder.embed(texts)
        rows  = []
        for j, (c, emb) in enumerate(zip(batch, embs)):
            meta = c["metadata"]
            rows.append((
                f"cis_chunk_{i + j}",
                meta.get("framework_id", "cis_v8"),
                c["content"],
                meta.get("node_id",      "") or "",
                meta.get("control_id",   "") or "",
                meta.get("safeguard_id", "") or "",
                meta.get("type",         "") or "",
                emb,
            ))
        execute_values(cur,
            f"""INSERT INTO {PG_TABLE}
                (id, framework_id, document, node_id,
                 control_id, safeguard_id, type, embedding)
                VALUES %s""",
            rows, template="(%s, %s, %s, %s, %s, %s, %s, %s::vector)",
        )
        conn.commit()
        done = min(i + BATCH, len(cis_chunks))
        print(f"\r  Progress: {done}/{len(cis_chunks)} ({round(done/len(cis_chunks)*100)}%)",
              end="", flush=True)
    counts["cis_v8"] = len(cis_chunks)
    print(f"\n  ✅ CIS v8.1 ingested: {len(cis_chunks)} chunks")

    # ── Step 4: Ingest NIST CSF 2.0 ──────────────────────────────────────────
    print(f"\n[2/3] NIST CSF 2.0 — reading PDF...")
    nist_text   = extract_pdf_text(NIST_DATA_PATH)
    nist_chunks = smart_chunk_nist(nist_text)
    print(f"  Extracted {len(nist_text):,} chars → {len(nist_chunks)} chunks")

    print(f"  Embedding & inserting {len(nist_chunks)} NIST chunks...")
    for i in range(0, len(nist_chunks), BATCH):
        batch = nist_chunks[i: i + BATCH]
        texts = [c["content"] for c in batch]
        embs  = embedder.embed(texts)
        rows  = []
        for j, (c, emb) in enumerate(zip(batch, embs)):
            meta = c["metadata"]
            rows.append((
                f"nist_chunk_{i + j}",
                meta.get("framework_id", "nist_csf"),
                c["content"],
                meta.get("node_id",      "") or "",
                meta.get("control_id",   "") or "",
                meta.get("safeguard_id", "") or "",
                meta.get("type",         "") or "",
                emb,
            ))
        execute_values(cur,
            f"""INSERT INTO {PG_TABLE}
                (id, framework_id, document, node_id,
                 control_id, safeguard_id, type, embedding)
                VALUES %s""",
            rows, template="(%s, %s, %s, %s, %s, %s, %s, %s::vector)",
        )
        conn.commit()
        done = min(i + BATCH, len(nist_chunks))
        print(f"\r  Progress: {done}/{len(nist_chunks)} ({round(done/len(nist_chunks)*100)}%)",
              end="", flush=True)
    counts["nist_csf"] = len(nist_chunks)
    print(f"\n  ✅ NIST CSF 2.0 ingested: {len(nist_chunks)} chunks")

# ── Step 5: Ingest HIPAA Security Rule ───────────────────────────────────
    print(f"\n[3/3] HIPAA Security Rule — reading JSON...")
    hipaa_chunks, skipped_h = smart_chunk_hipaa(hipaa_json)        # ← pass dict, not text
    print(f"  JSON parsed → {len(hipaa_chunks)} chunks ({skipped_h} skipped)")

    breakdown_h = {}
    for c in hipaa_chunks:
        t = c["metadata"]["type"]
        breakdown_h[t] = breakdown_h.get(t, 0) + 1
    print(f"  Chunk types: {breakdown_h}")

    print(f"  Embedding & inserting {len(hipaa_chunks)} HIPAA chunks...")
    for i in range(0, len(hipaa_chunks), BATCH):
        batch = hipaa_chunks[i: i + BATCH]
        texts = [c["content"] for c in batch]
        embs  = embedder.embed(texts)
        rows  = []
        for j, (c, emb) in enumerate(zip(batch, embs)):
            meta = c["metadata"]
            rows.append((
                f"hipaa_chunk_{i + j}",
                "hipaa_security_rule",
                c["content"],
                meta.get("node_id",      "") or "",
                meta.get("control_id",   "") or "",
                meta.get("safeguard_id", "") or "",
                meta.get("type",         "") or "",
                emb,
            ))
        execute_values(cur,
            f"""INSERT INTO {PG_TABLE}
                (id, framework_id, document, node_id,
                 control_id, safeguard_id, type, embedding)
                VALUES %s""",
            rows, template="(%s, %s, %s, %s, %s, %s, %s, %s::vector)",
        )
        conn.commit()
        done = min(i + BATCH, len(hipaa_chunks))
        print(f"\r  Progress: {done}/{len(hipaa_chunks)} ({round(done/len(hipaa_chunks)*100)}%)",
              end="", flush=True)
    counts["hipaa_security_rule"] = len(hipaa_chunks)
    print(f"\n  ✅ HIPAA Security Rule ingested: {len(hipaa_chunks)} chunks")

    # ── Step 6: Build IVFFlat index ───────────────────────────────────────────
    total = counts["cis_v8"] + counts["nist_csf"] + counts["hipaa_security_rule"]
    lists = max(10, min(100, total // 30))
    print(f"\nBuilding IVFFlat cosine index (lists={lists})...")
    cur.execute(f"""
        CREATE INDEX ON {PG_TABLE}
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = {lists});
    """)
    conn.commit()
    cur.close(); conn.close()

    counts["total"] = total
    print(f"\n{'=' * 72}")
    print(f"  Multi-framework ingestion complete")
    print(f"  CIS v8.1            : {counts['cis_v8']:>6} chunks")
    print(f"  NIST CSF 2.0        : {counts['nist_csf']:>6} chunks")
    print(f"  HIPAA Security Rule : {counts['hipaa_security_rule']:>6} chunks")
    print(f"  Total               : {counts['total']:>6} chunks")
    print(f"{'=' * 72}")
    return counts


def ingest_nist_to_graph(all_nist_subcats: set, nist_cats: set):
    conn = get_age_connection()
    print("\nIngesting NIST CSF 2.0 nodes into AGE graph...")

    # ── 1. Framework node ─────────────────────────────────────────────────────
    run_cypher(conn, cypher(AGE_GRAPH_NAME,
        """CREATE (:Framework {
            id:      'nist_csf',
            name:    'NIST Cybersecurity Framework',
            version: '2.0'
        })"""
    ))
    print("  ✓ NIST Framework node created")

    # ── 2. Category-level nodes (GV.OC, PR.AA, etc.) ─────────────────────────
    cat_count = 0
    for cat_id in sorted(nist_cats):
        func_id = cat_id.split(".")[0]
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:NISTCategory {{
                id:           '{cat_id}',
                level:        'category',
                function_id:  '{func_id}',
                framework_id: 'nist_csf'
            }})"""
        ))
        cat_count += 1

    # ── 3. Subcategory-level nodes — EXCLUDE any id already in nist_cats ──────
    # This prevents double-inserting e.g. "GV.OC" if it somehow appears in both sets
    subcat_ids_only = all_nist_subcats - nist_cats
    subcat_count = 0
    for subcat_id in sorted(subcat_ids_only):
        cat_id  = subcat_id.rsplit("-", 1)[0]
        func_id = cat_id.split(".")[0]
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:NISTCategory {{
                id:           '{subcat_id}',
                level:        'subcategory',
                category_id:  '{cat_id}',
                function_id:  '{func_id}',
                framework_id: 'nist_csf'
            }})"""
        ))
        subcat_count += 1

    print(f"  ✓ {cat_count} category nodes + {subcat_count} subcategory nodes = {cat_count + subcat_count} total NISTCategory nodes")

    # ── 4. MAPS_TO edges: CIS Control → NIST subcategory (SINGLE source of truth) ──
    maps_total = 0
    for ctrl_id, nist_ids in CIS_TO_NIST_MAPPINGS.items():
        # Deduplicate the mapping list itself before inserting
        for nist_id in sorted(set(nist_ids)):
            run_cypher(conn, cypher(AGE_GRAPH_NAME,
                f"""MATCH (c:Control      {{id: '{ctrl_id}'}}),
                          (n:NISTCategory {{id: '{nist_id}'}})
                    CREATE (c)-[:MAPS_TO]->(n)"""
            ))
            maps_total += 1
    print(f"  ✓ {maps_total} MAPS_TO edges created (CIS → NIST CSF 2.0)")

    conn.close()
    print("\n✅ NIST CSF 2.0 graph ingestion complete")

def diagnose_with_write_conn():
    """Use write connection same as ingest — avoids read replica lag."""
    conn = get_age_connection()   # ← write conn, not read conn
    cur  = conn.cursor()

    for label in ["Control", "NISTCategory", "Safeguard"]:
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH (n:{label}) RETURN count(n)
            $$) AS (cnt agtype);
        """)
        print(f"  {label}: {cur.fetchone()[0]}")

    for edge in ["MAPS_TO", "RELATED_TO"]:
        cur.execute(f"""
            SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
                MATCH ()-[r:{edge}]->() RETURN count(r)
            $$) AS (cnt agtype);
        """)
        print(f"  {edge}: {cur.fetchone()[0]}")

    # Check subcategory nodes specifically
    cur.execute(f"""
        SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
            MATCH (n:NISTCategory {{level: 'subcategory'}}) RETURN n.id LIMIT 5
        $$) AS (nist_id agtype);
    """)
    rows = cur.fetchall()
    print(f"  Subcategory sample: {[str(r[0]).strip(chr(34)) for r in rows]}")

    # Check MAPS_TO actually resolves
    cur.execute(f"""
        SELECT * FROM ag_catalog.cypher('{AGE_GRAPH_NAME}', $$
            MATCH (c:Control {{id: 'Control 6'}})-[:MAPS_TO]->(n:NISTCategory)
            RETURN n.id LIMIT 5
        $$) AS (nist_id agtype);
    """)
    rows = cur.fetchall()
    print(f"  Control 6 MAPS_TO: {[str(r[0]).strip(chr(34)) for r in rows]}")

    cur.close()
    conn.close()

def ingest_hipaa_to_graph():
    """
    Adds HIPAA Security Rule nodes and edges to the AGE compliance_graph.

    Node types reused (no schema changes needed):
      - Framework   → id='hipaa_security_rule'
      - Control     → each CFR section e.g. '164.308'     (mirrors CIS Control nodes)
      - Safeguard   → subsection e.g. '164.308a1'         (mirrors CIS Safeguard nodes)

    New edge type reused:
      - MAPS_TO     → CFR section → NISTCategory (same edge type as CIS→NIST)
      - RELATED_TO  → CFR section → CIS Control  (cross-framework relationship)
    """
    # Extend AGE schema with HIRAAControl and HIPAASafeguard labels
    # (we reuse Control/Safeguard labels with framework_id='hipaa_security_rule'
    #  so no new vlabels are needed — the existing schema already supports this)

    conn = get_age_connection()
    print("\nIngesting HIPAA Security Rule nodes into AGE graph...")

    # ── 1. Framework node ─────────────────────────────────────────────────────
    run_cypher(conn, cypher(AGE_GRAPH_NAME,
        """CREATE (:Framework {
            id:      'hipaa_security_rule',
            name:    'HIPAA Security Rule',
            version: '2025 NPRM'
        })"""
    ))
    print("  ✓ HIPAA Framework node created")

    # ── 2. CFR section Control nodes ──────────────────────────────────────────
    # Based on HIPAA_TO_NIST_MAPPINGS keys — these are the major sections
    # Build CFR section names from all sections present in HIPAA_TO_NIST_MAPPINGS.
    # The SCF 2026.1 data contains sections beyond the original 164.306-316 set.
    _CFR_KNOWN_NAMES = {
        "164.306": "General Rules — Security Standards",
        "164.308": "Administrative Safeguards",
        "164.310": "Physical Safeguards",
        "164.312": "Technical Safeguards",
        "164.314": "Organizational Requirements",
        "164.316": "Policies, Procedures and Documentation",
        "164.404": "Notification to Individuals",
        "164.408": "Notification to the Media",
        "164.410": "Notification by a Business Associate",
        "164.412": "Law Enforcement Delay",
        "164.502": "Uses and Disclosures of Protected Health Information",
        "164.504": "Uses and Disclosures — Organizational Requirements",
        "164.514": "Uses and Disclosures for Which an Authorization is Not Required",
        "164.530": "Administrative Requirements",
    }
    all_hipaa_sections = set(HIPAA_TO_NIST_MAPPINGS.keys())
    CFR_SECTION_NAMES = {
        s: _CFR_KNOWN_NAMES.get(s, f"HIPAA CFR {s}")
        for s in sorted(all_hipaa_sections)
    }

    for cfr_id, cfr_name in CFR_SECTION_NAMES.items():
        safe_name = cfr_name.replace("'", "\\'")
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:Control {{
                id:           '{cfr_id}',
                name:         '{safe_name}',
                framework_id: 'hipaa_security_rule'
            }})"""
        ))
    print(f"  ✓ {len(CFR_SECTION_NAMES)} HIPAA CFR section Control nodes created")

    # ── 3. Subsection Safeguard nodes + HAS_SAFEGUARD edges ───────────────────
    sfg_count = 0
    for subsec_id in sorted(HIPAA_TO_NIST_MAPPINGS.keys()):
        # Derive parent CFR section from subsection id
        # e.g. '164.308a1' → parent = '164.308'
        parent_cfr = re.match(r"(164\.\d{3})", subsec_id)
        parent_id  = parent_cfr.group(1) if parent_cfr else "164.300"

        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:Safeguard {{
                id:           '{subsec_id}',
                control_id:   '{parent_id}',
                framework_id: 'hipaa_security_rule'
            }})"""
        ))
        # HAS_SAFEGUARD: parent CFR section → subsection
        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""MATCH (c:Control   {{id: '{parent_id}'}}),
                      (s:Safeguard {{id: '{subsec_id}'}})
                CREATE (c)-[:HAS_SAFEGUARD]->(s)"""
        ))
        sfg_count += 1

    print(f"  ✓ {sfg_count} HIPAA Safeguard nodes + HAS_SAFEGUARD edges created")

    # ── 4. MAPS_TO edges: HIPAA subsection → NIST subcategory ─────────────────
    maps_count = 0
    for subsec_id, nist_ids in HIPAA_TO_NIST_MAPPINGS.items():
        for nist_id in sorted(set(nist_ids)):
            run_cypher(conn, cypher(AGE_GRAPH_NAME,
                f"""MATCH (h:Safeguard   {{id: '{subsec_id}'}}),
                          (n:NISTCategory {{id: '{nist_id}'}})
                    CREATE (h)-[:MAPS_TO]->(n)"""
            ))
            maps_count += 1
    print(f"  ✓ {maps_count} HIPAA→NIST MAPS_TO edges created")

    # ── 5. RELATED_TO edges: HIPAA CFR section → CIS Control ──────────────────
    # Cross-framework relationships — HIPAA section maps to overlapping CIS domain
    HIPAA_TO_CIS = {
        "164.308": ["Control 5", "Control 6", "Control 14", "Control 17"],  # Admin safeguards
        "164.310": ["Control 1", "Control 4", "Control 12"],                # Physical safeguards
        "164.312": ["Control 3", "Control 6", "Control 8", "Control 13"],   # Technical safeguards
        "164.306": ["Control 7", "Control 4"],                              # General standards
        "164.314": ["Control 15"],                                          # Business associates
        "164.316": ["Control 8"],                                           # Documentation
    }
    related_count = 0
    for hipaa_id, cis_ids in HIPAA_TO_CIS.items():
        for cis_id in cis_ids:
            run_cypher(conn, cypher(AGE_GRAPH_NAME,
                f"""MATCH (h:Control {{id: '{hipaa_id}'}}),
                          (c:Control {{id: '{cis_id}'}})
                    CREATE (h)-[:RELATED_TO]->(c)"""
            ))
            related_count += 1
    print(f"  ✓ {related_count} HIPAA→CIS RELATED_TO cross-framework edges created")

    # ADD this block at the end of ingest_hipaa_to_graph(), before conn.close():
    # ── 5. Implementation spec nodes from JSON ────────────────────────────────
    spec_count = 0
    for spec_code, spec_meta in HIPAA_SPEC_REGISTRY.items():
        cfr = spec_meta["cfr"]
        parent_cfr = re.match(r"(164\.\d{3})", cfr)
        parent_id  = parent_cfr.group(1) if parent_cfr else ""
        safe_name  = spec_meta["name"].replace("'", "\\'")
        desig      = spec_meta.get("designation", "")
        proposed   = spec_meta.get("proposed_2026", "")

        run_cypher(conn, cypher(AGE_GRAPH_NAME,
            f"""CREATE (:Safeguard {{
                id:           '{spec_code}',
                name:         '{safe_name}',
                cfr:          '{cfr}',
                control_id:   '{parent_id}',
                designation:  '{desig}',
                proposed_2026:'{proposed}',
                framework_id: 'hipaa_security_rule'
            }})"""
        ))
        spec_count += 1

    print(f"  ✓ {spec_count} HIPAA implementation spec Safeguard nodes created from JSON")

    conn.close()
    print("\n✅ HIPAA Security Rule graph ingestion complete")

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


# ── Run full setup when executed directly ─────────────────────────────────────
if __name__ == "__main__":
    """
    Run this script ONCE to build the data layer:
        python setup_ingestion.py

    Re-run when any of these change:
      - CIS v8.1 PDF
      - NIST CSF 2.0 PDF
      - HIPAA JSON
      - SCF Excel (after re-running phase1_scf_ingest.py)
    """
    import re
    from models import SecureBERTEmbedder
    from db_connections import CIS_TO_NIST_MAPPINGS, HIPAA_TO_NIST_MAPPINGS
    from config import EMBED_MODEL
    from hipaa_data import hipaa_json

    print("\n" + "=" * 72)
    print("  SETUP INGESTION — building data layer")
    print("=" * 72)

    # ── Step 1: Rebuild AGE graph ─────────────────────────────────────────────
    print("\nStep 1: Rebuilding AGE compliance_graph...")
    setup_age_graph()
    ingest_cis_to_graph()

    # Build NIST node ID sets from both CIS and HIPAA SCF mappings
    all_nist_subcats = set()
    nist_cats        = set()
    for nist_ids in list(CIS_TO_NIST_MAPPINGS.values()) + list(HIPAA_TO_NIST_MAPPINGS.values()):
        for nist_id in nist_ids:
            nist_id = nist_id.strip()
            if not nist_id or nist_id == "NAN":
                continue
            if not re.match(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$", nist_id):
                continue
            all_nist_subcats.add(nist_id)
            nist_cats.add(nist_id.rsplit("-", 1)[0])

    print(f"  NIST subcategory IDs : {len(all_nist_subcats)}")
    print(f"  NIST category IDs    : {len(nist_cats)}")

    ingest_nist_to_graph(all_nist_subcats, nist_cats)
    diagnose_with_write_conn()
    ingest_hipaa_to_graph()

    # ── Step 2: Rebuild pgvector compliance_chunks ────────────────────────────
    print("\nStep 2: Loading embedder and ingesting chunks...")
    _embedder = SecureBERTEmbedder(EMBED_MODEL)
    chunk_counts = setup_collection_multiframework(_embedder)

    print(f"\n✅ Setup complete.")
    print(f"   CIS v8.1            : {chunk_counts['cis_v8']} chunks")
    print(f"   NIST CSF 2.0        : {chunk_counts['nist_csf']} chunks")
    print(f"   HIPAA Security Rule : {chunk_counts['hipaa_security_rule']} chunks")
    print(f"   Total               : {chunk_counts['total']} chunks")
    print(f"   Graph doc count     : {get_pg_doc_count()}")
    print("\nSetup ingestion complete. You do not need to run this again")
    print("unless your source files (PDF/JSON/SCF) change.")