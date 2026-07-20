-- Furix — PostgreSQL tenant Row-Level Security schema (Wave-I / Epic 6).
--
-- The durable stores ship on SQLite (the tested, interface-compatible substrate).
-- This is the PRODUCTION target: the same tables in Postgres with tenant RLS, so
-- tenant isolation is enforced by the DATABASE, not just the application — a
-- defense-in-depth guarantee that survives an application bug that forgets a
-- `WHERE tenant = …`.
--
-- Usage: the app opens a connection as a NON-superuser role and, per request,
-- sets the tenant for the transaction:
--
--     SET app.current_tenant = 'acme';   -- (or SET LOCAL inside a txn)
--
-- Every policy below then scopes reads AND writes to that tenant automatically.
-- (Superusers and roles with BYPASSRLS ignore RLS — never run the app as one.)

-- A dedicated, least-privilege application role (no BYPASSRLS, not a superuser).
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'furix_app') THEN
    CREATE ROLE furix_app LOGIN;
  END IF;
END $$;

-- Helper: the current tenant for this session/transaction (NULL if unset →
-- policies deny everything, which is the safe default).
CREATE OR REPLACE FUNCTION furix_current_tenant() RETURNS text
  LANGUAGE sql STABLE AS $$ SELECT current_setting('app.current_tenant', true) $$;

-- ── the tenant-scoped durable tables (mirror the SQLite stores) ────────────────
CREATE TABLE IF NOT EXISTS admin_audit (
  tenant text NOT NULL, seq bigint NOT NULL, actor text NOT NULL, action text NOT NULL,
  target text NOT NULL DEFAULT '', outcome text NOT NULL DEFAULT 'ok', details jsonb NOT NULL,
  at timestamptz NOT NULL, prev_hash text NOT NULL, entry_hash text NOT NULL,
  PRIMARY KEY (tenant, seq));

CREATE TABLE IF NOT EXISTS attestations (
  att_id text NOT NULL, tenant text NOT NULL, spec_id text NOT NULL, status text NOT NULL,
  submitted_by text NOT NULL, submitted_at timestamptz NOT NULL, approvals jsonb NOT NULL DEFAULT '[]',
  required_approvals int NOT NULL DEFAULT 1, attestation jsonb NOT NULL,
  PRIMARY KEY (tenant, att_id));

CREATE TABLE IF NOT EXISTS control_profiles (
  tenant text NOT NULL, control_id text NOT NULL, profile jsonb NOT NULL,
  updated_at timestamptz, updated_by text, PRIMARY KEY (tenant, control_id));

CREATE TABLE IF NOT EXISTS audit_periods (
  tenant text NOT NULL, period_id text NOT NULL, status text NOT NULL,
  created_at timestamptz, period jsonb NOT NULL, PRIMARY KEY (tenant, period_id));

CREATE TABLE IF NOT EXISTS posture_runs (
  tenant text NOT NULL, run_id text NOT NULL, report_id text, completed_at timestamptz,
  status text NOT NULL, run jsonb NOT NULL, PRIMARY KEY (tenant, run_id));

CREATE TABLE IF NOT EXISTS connectors (
  tenant text NOT NULL, connector_id text NOT NULL, kind text NOT NULL,
  schedule_seconds int NOT NULL, enabled boolean NOT NULL DEFAULT true, config jsonb NOT NULL,
  next_run_at bigint, last_run_at bigint, last_status text, PRIMARY KEY (tenant, connector_id));

CREATE TABLE IF NOT EXISTS work_queue (
  job_id text PRIMARY KEY, tenant text NOT NULL, kind text NOT NULL, payload jsonb NOT NULL,
  status text NOT NULL, attempts int NOT NULL DEFAULT 0, run_after bigint NOT NULL DEFAULT 0,
  lease_expires bigint, worker text, last_error text, enqueued_at bigint NOT NULL);

CREATE TABLE IF NOT EXISTS scim_users (
  tenant text NOT NULL, id text NOT NULL, user_name text NOT NULL, external_id text,
  active boolean NOT NULL DEFAULT true, resource jsonb NOT NULL,
  created timestamptz NOT NULL, modified timestamptz NOT NULL, PRIMARY KEY (tenant, id));

-- ── enable RLS + the per-tenant policy on every table ──────────────────────────
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['admin_audit','attestations','control_profiles','audit_periods',
                           'posture_runs','connectors','work_queue','scim_users']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);   -- applies to the table owner too
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    -- reads AND writes are constrained to the session tenant; a NULL tenant denies all
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING (tenant = furix_current_tenant())
        WITH CHECK (tenant = furix_current_tenant())
    $f$, t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO furix_app', t);
  END LOOP;
END $$;

-- Multi-worker queue claim (the SKIP LOCKED upgrade over the SQLite lease):
--   SELECT * FROM work_queue WHERE status='queued' AND run_after <= extract(epoch from now())
--     ORDER BY enqueued_at FOR UPDATE SKIP LOCKED LIMIT 1;
-- lets many workers pull disjoint jobs concurrently without double-processing.
