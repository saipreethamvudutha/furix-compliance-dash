-- Runs once on first DB init (POSTGRES_DB defaults to furix_compliance).
-- Enables pgvector + AGE in the primary DB, then creates and equips furix_det.

-- ── primary DB: furix_compliance (pgvector chunks + AGE graph) ──
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- ── crosswalk DB: furix_det (SCF-derived tables) ──
CREATE DATABASE furix_det;
\connect furix_det
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS age;
