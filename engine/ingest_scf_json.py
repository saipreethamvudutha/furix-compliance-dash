"""
ingest_scf_json.py
==================
Phase 1 crosswalk ingest — populates the `furix_det` database from the Secure
Controls Framework machine-readable JSON (scf-full-2026.2.json).

This is the JSON-based replacement for `phase1_scf_ingest.py` (which parsed the
Excel workbook by fragile, version-specific column indices). It reuses the pure,
unit-tested `scf_crosswalk.derive_crosswalks()` and writes three edge tables
whose column names match what `db_connections.py` already queries, plus a new
`cis_to_pci` table (PCI DSS 4.0 support). Every edge stores `source_scf_ids`
provenance so an auditor can trace any mapping to the SCF controls that produced it.

Run on the server (needs psycopg2 + Postgres):
    FURIX_SCF_JSON=/path/scf-full-2026.2.json PG_HOST=... python ingest_scf_json.py

Tables created (drop + recreate, idempotent):
    cis_to_nist   (cis_control_id, nist_csf_id, source_scf_ids)   ← db_connections reads
    hipaa_to_nist (hipaa_section,  nist_csf_id, source_scf_ids)   ← db_connections reads
    cis_to_pci    (cis_control_id, pci_requirement, source_scf_ids) ← NEW (registry/db_connections)
"""

from __future__ import annotations

import sys

import psycopg2

from config import (
    PG_HOST, PG_PORT, PG_USER, PG_PASSWORD, PG_DBNAME_DET, SCF_JSON_PATH,
)
import scf_crosswalk


# ── database bootstrap ────────────────────────────────────────────────────────
def _maintenance_connection() -> psycopg2.extensions.connection:
    """Connect to the default 'postgres' DB to CREATE DATABASE furix_det."""
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname="postgres",
        user=PG_USER, password=PG_PASSWORD,
    )
    conn.autocommit = True  # CREATE DATABASE cannot run in a transaction
    return conn


def ensure_database() -> None:
    conn = _maintenance_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (PG_DBNAME_DET,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{PG_DBNAME_DET}";')
            print(f"✅ created database {PG_DBNAME_DET}")
        else:
            print(f"ℹ️  database {PG_DBNAME_DET} already exists")
        cur.close()
    finally:
        conn.close()


def _det_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME_DET,
        user=PG_USER, password=PG_PASSWORD,
    )


_SCHEMA = """
DROP TABLE IF EXISTS cis_to_nist   CASCADE;
DROP TABLE IF EXISTS hipaa_to_nist CASCADE;
DROP TABLE IF EXISTS cis_to_pci    CASCADE;

CREATE TABLE cis_to_nist (
    cis_control_id  TEXT NOT NULL,
    nist_csf_id     TEXT NOT NULL,
    source_scf_ids  TEXT[] NOT NULL DEFAULT '{}',
    scf_version     TEXT NOT NULL DEFAULT '2026.2',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cis_control_id, nist_csf_id)
);
CREATE TABLE hipaa_to_nist (
    hipaa_section   TEXT NOT NULL,
    nist_csf_id     TEXT NOT NULL,
    source_scf_ids  TEXT[] NOT NULL DEFAULT '{}',
    scf_version     TEXT NOT NULL DEFAULT '2026.2',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hipaa_section, nist_csf_id)
);
CREATE TABLE cis_to_pci (
    cis_control_id  TEXT NOT NULL,
    pci_requirement TEXT NOT NULL,
    source_scf_ids  TEXT[] NOT NULL DEFAULT '{}',
    scf_version     TEXT NOT NULL DEFAULT '2026.2',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cis_control_id, pci_requirement)
);
CREATE INDEX idx_cis_to_nist_cis   ON cis_to_nist   (cis_control_id);
CREATE INDEX idx_hipaa_to_nist_sec ON hipaa_to_nist (hipaa_section);
CREATE INDEX idx_cis_to_pci_cis    ON cis_to_pci    (cis_control_id);
"""


def _insert_edges(cur, table: str, left_col: str, right_col: str,
                  provenance: dict[tuple[str, str], list[str]]) -> int:
    rows = [
        (left, right, sources)
        for (left, right), sources in sorted(provenance.items())
    ]
    cur.executemany(
        f"INSERT INTO {table} ({left_col}, {right_col}, source_scf_ids) "
        f"VALUES (%s, %s, %s::TEXT[]) "
        f"ON CONFLICT ({left_col}, {right_col}) DO UPDATE "
        f"SET source_scf_ids = EXCLUDED.source_scf_ids;",
        rows,
    )
    return len(rows)


def ingest(scf_json_path: str = SCF_JSON_PATH) -> None:
    print(f"Deriving crosswalks from {scf_json_path} ...")
    cw = scf_crosswalk.derive_from_file(scf_json_path)
    print(f"  edges: cis→nist={cw.stats['cis_nist_edges']}  "
          f"hipaa→nist={cw.stats['hipaa_nist_edges']}  "
          f"cis→pci={cw.stats['cis_pci_edges']}")

    ensure_database()
    conn = _det_connection()
    try:
        cur = conn.cursor()
        cur.execute(_SCHEMA)
        n1 = _insert_edges(cur, "cis_to_nist",   "cis_control_id", "nist_csf_id",     cw.cis_nist_provenance)
        n2 = _insert_edges(cur, "hipaa_to_nist", "hipaa_section",  "nist_csf_id",     cw.hipaa_nist_provenance)
        n3 = _insert_edges(cur, "cis_to_pci",    "cis_control_id", "pci_requirement", cw.cis_pci_provenance)
        conn.commit()
        print(f"✅ furix_det populated: cis_to_nist={n1}  hipaa_to_nist={n2}  cis_to_pci={n3} rows")
        cur.close()
    finally:
        conn.close()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else SCF_JSON_PATH
    ingest(path)
