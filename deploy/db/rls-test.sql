-- Two-tenant Row-Level Security isolation test (Wave-J). Run AS the furix_app
-- role (non-superuser) AFTER applying rls-schema.sql, so the policies are
-- enforced. RAISEs an exception (non-zero psql exit) on any isolation failure.
--
--   psql "$DSN" -f rls-schema.sql
--   PGOPTIONS=... psql "postgres://furix_app@.../db" -v ON_ERROR_STOP=1 -f rls-test.sql

-- tenant acme writes a row
SET app.current_tenant = 'acme';
INSERT INTO scim_users (tenant, id, user_name, resource, created, modified)
  VALUES ('acme', 'u-acme', 'alice@acme', '{}'::jsonb, now(), now());

-- tenant globex must NOT see acme's row, and cannot write into acme
SET app.current_tenant = 'globex';
DO $$
BEGIN
  IF (SELECT count(*) FROM scim_users) <> 0 THEN
    RAISE EXCEPTION 'RLS FAIL: globex can read % acme row(s)', (SELECT count(*) FROM scim_users);
  END IF;
  BEGIN
    INSERT INTO scim_users (tenant, id, user_name, resource, created, modified)
      VALUES ('acme', 'u-forged', 'mallory', '{}'::jsonb, now(), now());
    RAISE EXCEPTION 'RLS FAIL: globex inserted a row scoped to acme';
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN
    NULL;  -- expected: WITH CHECK / USING blocked the cross-tenant write
  END;
END $$;

-- back as acme: sees exactly its own row
SET app.current_tenant = 'acme';
DO $$
BEGIN
  IF (SELECT count(*) FROM scim_users WHERE id = 'u-acme') <> 1 THEN
    RAISE EXCEPTION 'RLS FAIL: acme cannot read its own row';
  END IF;
  IF (SELECT count(*) FROM scim_users) <> 1 THEN
    RAISE EXCEPTION 'RLS FAIL: acme sees rows it should not';
  END IF;
END $$;

SELECT 'RLS two-tenant isolation: OK' AS result;
