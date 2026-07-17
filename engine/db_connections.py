"""
db_connections.py
=================
All database connection helpers for the Furix pipeline.

Three databases / connection types:
  get_pg_connection()       → cis_rag, pgvector registered (compliance_chunks)
  get_age_connection()      → cis_rag, autocommit + AGE loaded (write path)
  get_age_read_connection() → cis_rag, autocommit + AGE loaded (read path)
  get_det_connection()      → furix_det, plain psycopg2 (SCF crosswalk tables)

SCF crosswalk loader:
  _load_scf_crosswalks()    → queries furix_det and returns both mapping dicts
  CIS_TO_NIST_MAPPINGS      → loaded at module import, used everywhere
  HIPAA_TO_NIST_MAPPINGS    → loaded at module import, used everywhere
"""

import psycopg2
from pgvector.psycopg2 import register_vector
from openai import OpenAI

from config import (
    PG_HOST, PG_PORT, PG_DBNAME, PG_DBNAME_DET,
    PG_USER, PG_PASSWORD, MY_BASE_URL, LLM_MODEL,
)


# ── pgvector connection ───────────────────────────────────────────────────────
def get_pg_connection(register: bool = True) -> psycopg2.extensions.connection:
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
        user=PG_USER, password=PG_PASSWORD
    )
    if register:
        register_vector(conn)
    return conn


# ── AGE write connection ──────────────────────────────────────────────────────
def get_age_connection() -> psycopg2.extensions.connection:
    conn = psycopg2.connect(
        host="127.0.0.1", port=PG_PORT, dbname=PG_DBNAME,
        user=PG_USER, password=PG_PASSWORD
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("LOAD 'age';")
    cur.execute("SET search_path = ag_catalog, public;")
    cur.close()
    return conn


# ── AGE read connection ───────────────────────────────────────────────────────
def get_age_read_connection() -> psycopg2.extensions.connection:
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
        user=PG_USER, password=PG_PASSWORD
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("LOAD 'age';")
    cur.execute("SET search_path = ag_catalog, public;")
    cur.close()
    return conn


# ── furix_det connection (SCF crosswalk tables) ───────────────────────────────
def get_det_connection() -> psycopg2.extensions.connection:
    """Plain psycopg2 connection to furix_det — no pgvector registration needed."""
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME_DET,
        user=PG_USER, password=PG_PASSWORD
    )


# ── LLM client (Gemma, non-critical path only) ────────────────────────────────
nim_client = OpenAI(
    base_url=MY_BASE_URL,
    api_key="ollama",
)


# ── SCF crosswalk loader ──────────────────────────────────────────────────────
def _load_scf_crosswalks() -> tuple:
    """
    Loads CIS_TO_NIST_MAPPINGS and HIPAA_TO_NIST_MAPPINGS from furix_det.
    Source of truth: SCF 2026.1, built by phase1_scf_ingest.py.

    Returns:
        cis_dict   = {"Control 1": ["ID.AM-01", ...], ...}   (CIS  → NIST CSF)
        hipaa_dict = {"164.308":   ["PR.AA-01", ...], ...}   (HIPAA → NIST CSF)
        pci_dict   = {"Control 1": ["Req 12", ...],   ...}   (CIS  → PCI DSS 4.0)

    Order of preference: furix_det tables (populated by ingest_scf_json.py) →
    direct derivation from the SCF JSON (FURIX_SCF_JSON) → empty dicts.
    """
    cis_dict   = {}
    hipaa_dict = {}
    pci_dict   = {}
    try:
        conn = get_det_connection()
        cur  = conn.cursor()

        cur.execute(
            "SELECT cis_control_id, array_agg(nist_csf_id ORDER BY nist_csf_id) "
            "FROM cis_to_nist GROUP BY cis_control_id ORDER BY cis_control_id;"
        )
        for ctrl_id, nist_ids in cur.fetchall():
            cis_dict[ctrl_id] = nist_ids

        cur.execute(
            "SELECT hipaa_section, array_agg(nist_csf_id ORDER BY nist_csf_id) "
            "FROM hipaa_to_nist GROUP BY hipaa_section ORDER BY hipaa_section;"
        )
        for section, nist_ids in cur.fetchall():
            hipaa_dict[section] = nist_ids

        # cis_to_pci is optional — present only after the JSON ingest ran.
        try:
            cur.execute(
                "SELECT cis_control_id, array_agg(pci_requirement ORDER BY pci_requirement) "
                "FROM cis_to_pci GROUP BY cis_control_id ORDER BY cis_control_id;"
            )
            for ctrl_id, pci_ids in cur.fetchall():
                pci_dict[ctrl_id] = pci_ids
        except Exception:
            conn.rollback()  # table absent on an older furix_det — non-fatal

        cur.close()
        conn.close()
        print(f"✅ SCF crosswalks loaded from furix_det")
        print(f"   CIS controls  : {len(cis_dict)} entries")
        print(f"   HIPAA sections: {len(hipaa_dict)} entries")
        print(f"   PCI (via CIS)  : {len(pci_dict)} entries")
    except Exception as e:
        print(f"❌ WARNING: Could not load SCF crosswalks from furix_det: {e}")
        # Fallback: derive directly from the SCF JSON when the DB isn't populated.
        try:
            import os
            from config import SCF_JSON_PATH
            import scf_crosswalk
            scf_path = os.environ.get("FURIX_SCF_JSON", SCF_JSON_PATH)
            if os.path.exists(scf_path):
                cw = scf_crosswalk.derive_from_file(scf_path)
                cis_dict   = {k: list(v) for k, v in cw.cis_to_nist.items()}
                hipaa_dict = {k: list(v) for k, v in cw.hipaa_to_nist.items()}
                pci_dict   = {k: list(v) for k, v in cw.cis_to_pci.items()}
                print(f"↩︎  Fell back to SCF JSON crosswalk: {scf_path}")
                print(f"   CIS={len(cis_dict)} HIPAA={len(hipaa_dict)} PCI={len(pci_dict)}")
            else:
                print("   Run ingest_scf_json.py to populate furix_det (or set FURIX_SCF_JSON).")
        except Exception as e2:
            print(f"   SCF JSON fallback also unavailable: {e2}")
    return cis_dict, hipaa_dict, pci_dict


# Loaded once at import time — all modules that need these import from here
CIS_TO_NIST_MAPPINGS, HIPAA_TO_NIST_MAPPINGS, CIS_TO_PCI_MAPPINGS = _load_scf_crosswalks()


# ── Connection health check ───────────────────────────────────────────────────
def verify_connections() -> None:
    try:
        conn = get_pg_connection()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM pg_tables WHERE tablename = 'compliance_chunks';")
        exists = cur.fetchone()[0]
        cur.close(); conn.close()
        print(f"✅ pgvector (cis_rag) OK  — compliance_chunks exists: {bool(exists)}")
    except Exception as e:
        print(f"❌ pgvector (cis_rag) FAILED: {e}")

    try:
        conn = get_age_connection()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM ag_catalog.ag_graph;")
        graphs = cur.fetchall()
        cur.close(); conn.close()
        print(f"✅ AGE (cis_rag) OK  — graphs: {[g[0] for g in graphs] if graphs else 'none yet'}")
    except Exception as e:
        print(f"❌ AGE (cis_rag) FAILED: {e}")

    try:
        conn = get_det_connection()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cis_to_nist;")
        cis_rows = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hipaa_to_nist;")
        hipaa_rows = cur.fetchone()[0]
        cur.close(); conn.close()
        print(f"✅ furix_det OK  — cis_to_nist: {cis_rows} rows, hipaa_to_nist: {hipaa_rows} rows")
    except Exception as e:
        print(f"❌ furix_det FAILED: {e}")
        print("   Run phase1_scf_ingest.py to create and populate furix_det.")


if __name__ == "__main__":
    verify_connections()
