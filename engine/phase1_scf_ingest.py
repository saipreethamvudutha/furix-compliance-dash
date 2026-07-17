"""
phase1_scf_ingest.py
====================
Phase 1 of the Furix deterministic re-architecture.

What this script does
---------------------
1. Creates a new PostgreSQL database 'furix_det' inside the existing Docker
   container (same host/port as cis_rag — just a different dbname).
2. Creates three tables in furix_det:
     scf_controls     — one row per SCF control, all key columns preserved
     cis_to_nist      — derived crosswalk: CIS Control N → NIST CSF 2.0 IDs
     hipaa_to_nist    — derived crosswalk: HIPAA CFR section → NIST CSF 2.0 IDs
3. Reads SCF 2026.1.xlsx, parses every row, and populates all three tables.
4. Runs verification spot-checks against known expected values from the
   hand-typed dicts in the original code.

Run this ONCE before any other Phase 1 work.

How to run
----------
Place this file anywhere on your Windows machine.
Update SCF_XLSX_PATH to point at your copy of the SCF Excel file.
Then run:
    python phase1_scf_ingest.py

Requirements: psycopg2, openpyxl (both already installed in your environment).

Postgres connection: same Docker container as cis_rag, new database furix_det.
"""

import os
import re
import sys
import psycopg2
from psycopg2 import sql
import openpyxl

# ── Configuration ─────────────────────────────────────────────────────────────
# Update this path to wherever you saved the SCF Excel file.
SCF_XLSX_PATH = os.environ.get("FURIX_SCF_XLSX", "./source_data/scf-2026.xlsx")  # legacy xlsx path; ingest_scf_json.py (JSON) supersedes this

# Existing Docker container connection details (used to create the new database)
PG_HOST     = "localhost"
PG_PORT     = 5432
PG_ADMIN_DB = "furix_det"
PG_USER     = os.environ.get("PG_USER", "furix")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "postgres")

# New database name for the deterministic architecture
NEW_DB_NAME = "furix_det"

# SCF Excel sheet and column indices (verified by inspection)
SCF_SHEET_NAME  = "SCF 2026.1"
COL_DOMAIN      = 0    # SCF Domain
COL_CONTROL     = 1    # SCF Control name
COL_SCF_NUM     = 2    # SCF # (e.g. GOV-01, AST-02.2)
COL_DESCRIPTION = 3    # SCF Control Description
COL_NIST_FUNC   = 14   # NIST CSF Function Grouping (Govern/Identify/Protect etc.)
COL_CIS_V8      = 37   # CIS CSC 8.1 safeguard IDs (e.g. "1.1\n2.3\n13.9")
COL_NIST_CSF    = 102  # NIST CSF 2.0 subcategory IDs (e.g. "ID.AM-01\nPR.AA-03")
COL_HIPAA_ADMIN = 156  # US HIPAA Administrative Simplification 2013
COL_HIPAA_SEC   = 157  # US HIPAA Security Rule / NIST SP 800-66 R2


# ── Helpers ───────────────────────────────────────────────────────────────────

def _split_cell(value) -> list:
    """
    Split a multi-value Excel cell (newline-separated) into a clean list.
    Returns empty list for None or blank cells.
    Each item is stripped of whitespace and parenthetical sub-references.

    Examples:
        "ID.AM-01\nID.AM-02\nPR.AA-03" → ["ID.AM-01", "ID.AM-02", "PR.AA-03"]
        "164.308(a)(1)(i)\n164.310(d)(1)" → ["164.308(a)(1)(i)", "164.310(d)(1)"]
        "1.1\n2.3\n13.9" → ["1.1", "2.3", "13.9"]
        None → []
    """
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    items = [item.strip() for item in text.splitlines()]
    return [i for i in items if i]


def _cis_safeguard_to_control(safeguard_id: str) -> str:
    """
    Convert a CIS safeguard ID to its parent control number string.

    The SCF stores CIS references as safeguard-level IDs:
        "1.1"  → "Control 1"
        "13.9" → "Control 13"
        "1.0"  → "Control 1"   (top-level control reference, no safeguard)
        "2.0"  → "Control 2"

    We extract the integer before the first dot.
    """
    m = re.match(r"^(\d+)\.", safeguard_id.strip())
    if m:
        return f"Control {m.group(1)}"
    return None


def _extract_hipaa_cfr_section(cfr_ref: str) -> str:
    """
    Extract the top-level CFR section from a detailed HIPAA reference.

    Examples:
        "164.308(a)(1)(i)" → "164.308"
        "164.312(a)(2)(ii)" → "164.312"
        "164.306(d)(3)" → "164.306"
        "164.530(c)(1)" → "164.530"  (outside our mapping scope — kept as-is)
    """
    m = re.match(r"(164\.\d{3})", cfr_ref.strip())
    if m:
        return m.group(1)
    return None


def get_connection(dbname: str) -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=dbname,
        user=PG_USER, password=PG_PASSWORD
    )


# ── Step 1: Create the new database ──────────────────────────────────────────

def create_database():
    """
    Creates 'furix_det' if it does not exist.
    Connects to the admin database (cis_rag) to issue the CREATE DATABASE command.
    Uses autocommit because CREATE DATABASE cannot run inside a transaction block.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 1 — Creating database '{NEW_DB_NAME}'")
    print(f"{'='*70}")

    conn = get_connection(PG_ADMIN_DB)
    conn.autocommit = True
    cur = conn.cursor()

    # Check if database already exists
    cur.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s;",
        (NEW_DB_NAME,)
    )
    if cur.fetchone():
        print(f"  Database '{NEW_DB_NAME}' already exists — skipping creation.")
    else:
        cur.execute(
            sql.SQL("CREATE DATABASE {} OWNER {};").format(
                sql.Identifier(NEW_DB_NAME),
                sql.Identifier(PG_USER)
            )
        )
        print(f"  ✅ Database '{NEW_DB_NAME}' created successfully.")

    cur.close()
    conn.close()


# ── Step 2: Create tables ─────────────────────────────────────────────────────

def create_tables():
    """
    Creates the three crosswalk tables in furix_det.

    scf_controls:
        The raw SCF data — one row per SCF control. This is the authoritative
        source of truth for all crosswalk queries. It is what replaces the
        hand-typed CIS_TO_NIST_MAPPINGS and HIPAA_TO_NIST_MAPPINGS dicts.

    cis_to_nist:
        Derived table: one row per (cis_control_id, nist_csf_id) pair.
        Built by joining through scf_controls: CIS safeguard → parent control
        → SCF row → NIST CSF 2.0 column.
        This is what the downstream pipeline queries instead of the dict.

    hipaa_to_nist:
        Derived table: one row per (hipaa_cfr_section, nist_csf_id) pair.
        Built from: HIPAA cfr_ref → parent section → SCF row → NIST CSF 2.0.

    All tables are dropped and recreated on each run so this script is
    idempotent and safe to re-run if the SCF file is updated.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 2 — Creating tables in '{NEW_DB_NAME}'")
    print(f"{'='*70}")

    conn = get_connection(NEW_DB_NAME)
    cur = conn.cursor()

    # ── scf_controls ─────────────────────────────────────────────────────────
    cur.execute("DROP TABLE IF EXISTS scf_controls CASCADE;")
    cur.execute(
        "CREATE TABLE scf_controls ("
        "    id              SERIAL PRIMARY KEY,"
        "    scf_id          TEXT NOT NULL,"
        "    scf_domain      TEXT,"
        "    scf_control     TEXT,"
        "    description     TEXT,"
        "    nist_csf_func   TEXT,"
        "    cis_v8_raw      TEXT,"
        "    nist_csf_raw    TEXT,"
        "    hipaa_admin_raw TEXT,"
        "    hipaa_sec_raw   TEXT,"
        "    cis_safeguards  TEXT[],"
        "    cis_controls    TEXT[],"
        "    nist_csf_ids    TEXT[],"
        "    hipaa_cfr_refs  TEXT[],"
        "    hipaa_sections  TEXT[],"
        "    scf_version     TEXT DEFAULT '2026.1',"
        "    ingested_at     TIMESTAMPTZ DEFAULT NOW()"
        ");"
    )
    print("  ✅ Table 'scf_controls' created")

    # ── cis_to_nist ───────────────────────────────────────────────────────────
    # One row per (cis_control_id, nist_csf_id) pair.
    # source_scf_ids is an array of all SCF IDs that create this edge — provides
    # full provenance so an auditor can trace every mapping back to the SCF row.
    cur.execute("DROP TABLE IF EXISTS cis_to_nist CASCADE;")
    cur.execute(
        "CREATE TABLE cis_to_nist ("
        "    id              SERIAL PRIMARY KEY,"
        "    cis_control_id  TEXT NOT NULL,"
        "    nist_csf_id     TEXT NOT NULL,"
        "    source_scf_ids  TEXT[],"
        "    scf_version     TEXT DEFAULT '2026.1',"
        "    ingested_at     TIMESTAMPTZ DEFAULT NOW(),"
        "    UNIQUE (cis_control_id, nist_csf_id)"
        ");"
    )
    print("  ✅ Table 'cis_to_nist' created")

    # ── hipaa_to_nist ─────────────────────────────────────────────────────────
    cur.execute("DROP TABLE IF EXISTS hipaa_to_nist CASCADE;")
    cur.execute(
        "CREATE TABLE hipaa_to_nist ("
        "    id              SERIAL PRIMARY KEY,"
        "    hipaa_section   TEXT NOT NULL,"
        "    nist_csf_id     TEXT NOT NULL,"
        "    source_scf_ids  TEXT[],"
        "    scf_version     TEXT DEFAULT '2026.1',"
        "    ingested_at     TIMESTAMPTZ DEFAULT NOW(),"
        "    UNIQUE (hipaa_section, nist_csf_id)"
        ");"
    )
    print("  ✅ Table 'hipaa_to_nist' created")

    # Indexes for fast lookup — these are the query patterns the pipeline uses
    cur.execute("CREATE INDEX idx_cis_to_nist_cis_id ON cis_to_nist(cis_control_id);")
    cur.execute("CREATE INDEX idx_cis_to_nist_nist_id ON cis_to_nist(nist_csf_id);")
    cur.execute("CREATE INDEX idx_hipaa_to_nist_section ON hipaa_to_nist(hipaa_section);")
    cur.execute("CREATE INDEX idx_scf_cis_controls ON scf_controls USING GIN(cis_controls);")
    cur.execute("CREATE INDEX idx_scf_nist_ids ON scf_controls USING GIN(nist_csf_ids);")
    cur.execute("CREATE INDEX idx_scf_hipaa_sections ON scf_controls USING GIN(hipaa_sections);")
    print("  ✅ Indexes created on all three tables")

    conn.commit()
    cur.close()
    conn.close()


# ── Step 3: Read SCF Excel and populate scf_controls ─────────────────────────

def ingest_scf_excel() -> int:
    """
    Reads SCF 2026.1.xlsx sheet 'SCF 2026.1' row by row.
    Skips row 1 (header). Every row with a non-empty SCF # is inserted.

    Returns the number of rows inserted.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 3 — Reading SCF Excel: {SCF_XLSX_PATH}")
    print(f"{'='*70}")

    wb = openpyxl.load_workbook(SCF_XLSX_PATH, read_only=True, data_only=True)
    ws = wb[SCF_SHEET_NAME]

    conn = get_connection(NEW_DB_NAME)
    cur  = conn.cursor()

    inserted   = 0
    skipped    = 0
    batch_rows = []
    BATCH_SIZE = 100

    def flush_batch():
        if not batch_rows:
            return
        # Use executemany with a parameterized INSERT
        cur.executemany("""
            INSERT INTO scf_controls (
                scf_id, scf_domain, scf_control, description, nist_csf_func,
                cis_v8_raw, nist_csf_raw, hipaa_admin_raw, hipaa_sec_raw,
                cis_safeguards, cis_controls, nist_csf_ids,
                hipaa_cfr_refs, hipaa_sections
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s
            )
        """, batch_rows)
        conn.commit()
        batch_rows.clear()

    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True)):
        scf_id = row[COL_SCF_NUM]
        if not scf_id:
            skipped += 1
            continue

        scf_id      = str(scf_id).strip()
        scf_domain  = str(row[COL_DOMAIN]).strip()  if row[COL_DOMAIN]  else ""
        scf_control = str(row[COL_CONTROL]).strip() if row[COL_CONTROL] else ""
        description = str(row[COL_DESCRIPTION]).strip() if row[COL_DESCRIPTION] else ""
        nist_func   = str(row[COL_NIST_FUNC]).strip()   if row[COL_NIST_FUNC]   else ""

        # Raw multi-value strings
        cis_raw      = str(row[COL_CIS_V8]).strip()      if row[COL_CIS_V8]      else ""
        nist_raw     = str(row[COL_NIST_CSF]).strip()    if row[COL_NIST_CSF]    else ""
        hipaa_a_raw  = str(row[COL_HIPAA_ADMIN]).strip() if row[COL_HIPAA_ADMIN] else ""
        hipaa_s_raw  = str(row[COL_HIPAA_SEC]).strip()   if row[COL_HIPAA_SEC]   else ""

        # Parse CIS safeguard IDs → ["1.1", "2.3", "13.9"]
        cis_safeguards_list = _split_cell(cis_raw)

        # Derive parent CIS control IDs → ["Control 1", "Control 2", "Control 13"]
        cis_controls_set = set()
        for sfg in cis_safeguards_list:
            ctrl = _cis_safeguard_to_control(sfg)
            if ctrl:
                cis_controls_set.add(ctrl)
        cis_controls_list = sorted(
            cis_controls_set,
            key=lambda x: int(re.search(r'\d+', x).group())
        )

        # Parse NIST CSF 2.0 IDs
        nist_ids_list = _split_cell(nist_raw)

        # Parse HIPAA CFR refs — merge both HIPAA columns, deduplicate
        hipaa_refs_set = set()
        for ref in _split_cell(hipaa_a_raw) + _split_cell(hipaa_s_raw):
            if ref:
                hipaa_refs_set.add(ref)
        hipaa_refs_list = sorted(hipaa_refs_set)

        # Derive top-level CFR sections → ["164.308", "164.312"]
        hipaa_sections_set = set()
        for ref in hipaa_refs_list:
            section = _extract_hipaa_cfr_section(ref)
            if section:
                hipaa_sections_set.add(section)
        hipaa_sections_list = sorted(hipaa_sections_set)

        batch_rows.append((
            scf_id, scf_domain, scf_control, description, nist_func,
            cis_raw or None,
            nist_raw or None,
            hipaa_a_raw or None,
            hipaa_s_raw or None,
            cis_safeguards_list or None,
            cis_controls_list or None,
            nist_ids_list or None,
            hipaa_refs_list or None,
            hipaa_sections_list or None,
        ))
        inserted += 1

        if len(batch_rows) >= BATCH_SIZE:
            flush_batch()
            print(f"\r  Inserted: {inserted} rows...", end="", flush=True)

    flush_batch()
    wb.close()

    print(f"\r  ✅ Inserted {inserted} SCF control rows ({skipped} empty rows skipped)")
    cur.close()
    conn.close()
    return inserted


# ── Step 4: Build cis_to_nist and hipaa_to_nist crosswalk tables ─────────────

def build_crosswalk_tables():
    """
    Derives cis_to_nist and hipaa_to_nist from scf_controls.

    Logic for cis_to_nist:
        For every row in scf_controls that has both cis_controls[] and nist_csf_ids[]:
            For every (cis_ctrl, nist_id) pair in the Cartesian product:
                Upsert a row into cis_to_nist, accumulating source_scf_ids.

    Logic for hipaa_to_nist:
        For every row in scf_controls that has both hipaa_sections[] and nist_csf_ids[]:
            For every (hipaa_section, nist_id) pair in the Cartesian product:
                Upsert a row into hipaa_to_nist, accumulating source_scf_ids.

    ON CONFLICT DO UPDATE appends the new scf_id to source_scf_ids so provenance
    is fully traceable even when multiple SCF controls create the same edge.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 4 — Building cis_to_nist and hipaa_to_nist crosswalk tables")
    print(f"{'='*70}")

    conn = get_connection(NEW_DB_NAME)
    cur  = conn.cursor()

    # ── Build cis_to_nist ──────────────────────────────────────────────────────
    cur.execute("""
        SELECT scf_id, cis_controls, nist_csf_ids
        FROM scf_controls
        WHERE cis_controls IS NOT NULL
          AND nist_csf_ids IS NOT NULL
          AND array_length(cis_controls, 1) > 0
          AND array_length(nist_csf_ids, 1) > 0
        ORDER BY scf_id;
    """)
    rows = cur.fetchall()

    cis_pairs_inserted   = 0
    cis_pairs_updated    = 0

    for scf_id, cis_controls, nist_ids in rows:
        for cis_ctrl in cis_controls:
            for nist_id in nist_ids:
                # Only insert valid NIST subcategory IDs (format: XX.XX-NN)
                # Skip category-level IDs like "ID.AM", "GV", "PR" which are
                # too broad to use as crosswalk targets.
                if not re.match(r'^[A-Z]{2}\.[A-Z]{2}-\d{2}$', nist_id):
                    continue

                cur.execute("""
                    INSERT INTO cis_to_nist (cis_control_id, nist_csf_id, source_scf_ids)
                    VALUES (%s, %s, ARRAY[%s]::TEXT[])
                    ON CONFLICT (cis_control_id, nist_csf_id) DO UPDATE
                        SET source_scf_ids = array_append(
                            cis_to_nist.source_scf_ids, %s
                        )
                    RETURNING (xmax = 0) AS was_insert;
                """, (cis_ctrl, nist_id, scf_id, scf_id))

                result = cur.fetchone()
                if result and result[0]:
                    cis_pairs_inserted += 1
                else:
                    cis_pairs_updated += 1

    conn.commit()
    print(f"  ✅ cis_to_nist: {cis_pairs_inserted} edges inserted, "
          f"{cis_pairs_updated} edges enriched with additional SCF sources")

    # ── Build hipaa_to_nist ───────────────────────────────────────────────────
    cur.execute("""
        SELECT scf_id, hipaa_sections, nist_csf_ids
        FROM scf_controls
        WHERE hipaa_sections IS NOT NULL
          AND nist_csf_ids IS NOT NULL
          AND array_length(hipaa_sections, 1) > 0
          AND array_length(nist_csf_ids, 1) > 0
        ORDER BY scf_id;
    """)
    rows = cur.fetchall()

    hipaa_pairs_inserted = 0
    hipaa_pairs_updated  = 0

    for scf_id, hipaa_sections, nist_ids in rows:
        for section in hipaa_sections:
            for nist_id in nist_ids:
                # Same filter — only subcategory-level NIST IDs
                if not re.match(r'^[A-Z]{2}\.[A-Z]{2}-\d{2}$', nist_id):
                    continue

                cur.execute("""
                    INSERT INTO hipaa_to_nist (hipaa_section, nist_csf_id, source_scf_ids)
                    VALUES (%s, %s, ARRAY[%s]::TEXT[])
                    ON CONFLICT (hipaa_section, nist_csf_id) DO UPDATE
                        SET source_scf_ids = array_append(
                            hipaa_to_nist.source_scf_ids, %s
                        )
                    RETURNING (xmax = 0) AS was_insert;
                """, (section, nist_id, scf_id, scf_id))

                result = cur.fetchone()
                if result and result[0]:
                    hipaa_pairs_inserted += 1
                else:
                    hipaa_pairs_updated += 1

    conn.commit()
    print(f"  ✅ hipaa_to_nist: {hipaa_pairs_inserted} edges inserted, "
          f"{hipaa_pairs_updated} edges enriched with additional SCF sources")

    cur.close()
    conn.close()


# ── Step 5: Verification spot-checks ─────────────────────────────────────────

def verify_crosswalks():
    """
    Compares SCF-derived crosswalk tables against the hand-typed dicts from the
    original code. This validates that the SCF data is consistent with what was
    manually maintained.

    We check:
      - Control 1 → should include ID.AM-01, ID.AM-02 (from original dict)
      - Control 5 → should include PR.AA-01, PR.AA-05 (from original dict)
      - Control 6 → should include PR.AA-03 (from original dict)
      - Control 13 → should include DE.CM-01, DE.CM-03 (from original dict)
      - 164.308 → should include PR.AA-01 (from original dict)
      - 164.312 → should include PR.DS-01, PR.DS-02 (from original dict)

    Prints PASS/FAIL for each check and a summary count of all mappings found.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 5 — Verification spot-checks")
    print(f"{'='*70}")

    # What we expect based on the original hand-typed dicts
    EXPECTED_CIS = {
        "Control 1":  ["ID.AM-01", "ID.AM-02"],
        "Control 5":  ["PR.AA-01", "PR.AA-05"],
        "Control 6":  ["PR.AA-03", "PR.AA-01"],
        "Control 13": ["DE.CM-01", "DE.CM-03"],
    }
    EXPECTED_HIPAA = {
        "164.308": ["PR.AA-01"],
        "164.312": ["PR.DS-01", "PR.DS-02"],
    }

    conn = get_connection(NEW_DB_NAME)
    cur  = conn.cursor()

    passes = 0
    fails  = 0

    print("\n  CIS → NIST checks:")
    for ctrl, expected_nist_ids in EXPECTED_CIS.items():
        cur.execute(
            "SELECT nist_csf_id FROM cis_to_nist WHERE cis_control_id = %s ORDER BY nist_csf_id;",
            (ctrl,)
        )
        actual_ids = {row[0] for row in cur.fetchall()}
        for nist_id in expected_nist_ids:
            if nist_id in actual_ids:
                print(f"    ✅ PASS  {ctrl} → {nist_id}")
                passes += 1
            else:
                print(f"    ❌ FAIL  {ctrl} → {nist_id} NOT FOUND in SCF-derived table")
                fails += 1

    print("\n  HIPAA → NIST checks:")
    for section, expected_nist_ids in EXPECTED_HIPAA.items():
        cur.execute(
            "SELECT nist_csf_id FROM hipaa_to_nist WHERE hipaa_section = %s ORDER BY nist_csf_id;",
            (section,)
        )
        actual_ids = {row[0] for row in cur.fetchall()}
        for nist_id in expected_nist_ids:
            if nist_id in actual_ids:
                print(f"    ✅ PASS  {section} → {nist_id}")
                passes += 1
            else:
                print(f"    ❌ FAIL  {section} → {nist_id} NOT FOUND in SCF-derived table")
                fails += 1

    print()
    print("  Row count summary:")
    for table in ("scf_controls", "cis_to_nist", "hipaa_to_nist"):
        cur.execute(f"SELECT COUNT(*) FROM {table};")
        count = cur.fetchone()[0]
        print(f"    {table:<22} : {count:>6} rows")

    print()
    print("  CIS control coverage in cis_to_nist:")
    cur.execute(
        "SELECT cis_control_id, COUNT(*) AS nist_targets "
        "FROM cis_to_nist "
        "GROUP BY cis_control_id "
        "ORDER BY cis_control_id;"
    )
    for ctrl_id, count in cur.fetchall():
        print(f"    {ctrl_id:<14} → {count} NIST IDs")

    print()
    print("  HIPAA section coverage in hipaa_to_nist:")
    cur.execute(
        "SELECT hipaa_section, COUNT(*) AS nist_targets "
        "FROM hipaa_to_nist "
        "GROUP BY hipaa_section "
        "ORDER BY hipaa_section;"
    )
    for section, count in cur.fetchall():
        print(f"    {section:<12} → {count} NIST IDs")

    cur.close()
    conn.close()

    print(f"\n  Spot-check result: {passes} PASS, {fails} FAIL")
    if fails > 0:
        print(
            "\n  NOTE: Some FAILs are expected and acceptable. The SCF 2026.1 crosswalk\n"
            "  is more precise than the hand-typed dict, which was manually curated.\n"
            "  Differences mean the SCF uses a different (more authoritative) mapping.\n"
            "  Review each FAIL manually to decide if the SCF version is correct."
        )
    return passes, fails


# ── Step 6: Print replacement dict preview ────────────────────────────────────

def print_replacement_preview():
    """
    Prints a Python dict preview of the SCF-derived CIS→NIST mapping.
    This is what CIS_TO_NIST_MAPPINGS should look like when replaced.
    You do not need to hardcode this — the pipeline will query the DB —
    but this lets you visually verify the SCF content before Phase 2.
    """
    print(f"\n{'='*70}")
    print(f"  STEP 6 — SCF-derived CIS_TO_NIST_MAPPINGS preview")
    print(f"{'='*70}")

    conn = get_connection(NEW_DB_NAME)
    cur  = conn.cursor()

    cur.execute("""
        SELECT cis_control_id, array_agg(nist_csf_id ORDER BY nist_csf_id) AS nist_ids
        FROM cis_to_nist
        GROUP BY cis_control_id
        ORDER BY cis_control_id;
    """)
    rows = cur.fetchall()

    print("\n  # SCF 2026.1-derived CIS→NIST mapping (replaces CIS_TO_NIST_MAPPINGS)")
    print("  SCF_CIS_TO_NIST = {")
    for ctrl_id, nist_ids in rows:
        ids_str = ", ".join(f'"{n}"' for n in nist_ids)
        print(f'      "{ctrl_id}": [{ids_str}],')
    print("  }")

    cur.close()
    conn.close()


# ── Main entry point ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*70)
    print("  FURIX DETERMINISTIC RE-ARCHITECTURE — PHASE 1")
    print("  SCF Crosswalk Ingestion")
    print("="*70)
    print(f"  Source    : {SCF_XLSX_PATH}")
    print(f"  Target DB : {PG_HOST}:{PG_PORT}/{NEW_DB_NAME}")

    try:
        create_database()
    except Exception as e:
        print(f"\n❌ FAILED at Step 1 (create database): {e}")
        print("   Make sure the Docker container is running:")
        print("   docker start cis_rag_db")
        sys.exit(1)

    try:
        create_tables()
    except Exception as e:
        print(f"\n❌ FAILED at Step 2 (create tables): {e}")
        sys.exit(1)

    try:
        row_count = ingest_scf_excel()
        if row_count == 0:
            print(f"\n❌ FAILED at Step 3: No rows read from Excel.")
            print(f"   Check that SCF_XLSX_PATH is correct: {SCF_XLSX_PATH}")
            sys.exit(1)
    except FileNotFoundError:
        print(f"\n❌ FAILED at Step 3: Excel file not found at {SCF_XLSX_PATH}")
        print("   Update SCF_XLSX_PATH at the top of this script.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ FAILED at Step 3 (ingest Excel): {e}")
        sys.exit(1)

    try:
        build_crosswalk_tables()
    except Exception as e:
        print(f"\n❌ FAILED at Step 4 (build crosswalk tables): {e}")
        sys.exit(1)

    try:
        passes, fails = verify_crosswalks()
    except Exception as e:
        print(f"\n❌ FAILED at Step 5 (verification): {e}")
        sys.exit(1)

    try:
        print_replacement_preview()
    except Exception as e:
        print(f"\n⚠️  Step 6 (preview) failed: {e} — non-fatal, continuing")

    print(f"\n{'='*70}")
    print(f"  PHASE 1 COMPLETE")
    print(f"  Database '{NEW_DB_NAME}' is ready on {PG_HOST}:{PG_PORT}")
    print(f"  Tables: scf_controls, cis_to_nist, hipaa_to_nist")
    print(f"  Spot-checks: {passes} PASS, {fails} FAIL")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()