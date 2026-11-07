-- PostgreSQL DDL for identity audit log table.
-- Embedded resource — executed at module startup by
-- IdentityAuditLogTableInitListener via redb.Context.ExecuteAsync.
-- Idempotent (IF NOT EXISTS) so re-running on an existing database is safe.

CREATE TABLE IF NOT EXISTS identity_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    event_id     UUID NOT NULL,
    event_type   VARCHAR(100) NOT NULL,
    category     VARCHAR(50),
    "timestamp"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- BIGINT (not VARCHAR) — every event we emit carries an internal
    -- redb _users.id, which is bigint. Smaller fixed-width index, direct
    -- integer compare, no text collation overhead. Emitters that hand us
    -- non-numeric identifiers (e.g. pre-link federated provider subjects)
    -- log a warning and land user_id = NULL — they still get filed under
    -- login + details.
    user_id      BIGINT,
    login        VARCHAR(200),
    client_id    VARCHAR(200),
    ip_address   VARCHAR(50),
    user_agent   VARCHAR(500),
    -- Stored as text (not jsonb) so the dialect-agnostic parameter binding
    -- in IRedbContext.ExecuteAsync — string-typed positional args — round-trips
    -- without a per-driver cast. Querying by individual keys was never the use
    -- case here (operators slice by event_type / user_id / login / timestamp).
    -- Operators wanting jsonb queries can ALTER the column locally; the audit
    -- query path doesn't read this column for filtering.
    details      TEXT,
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);

-- Reconcile an existing table.
--
-- CREATE TABLE IF NOT EXISTS above is a no-op when the table is already there, which means a database
-- created before a column existed never gains it — and nothing says so. The audit query selects `category`
-- and `login`, so on such a database it fails with `column "category" does not exist`, the route's
-- DbException handler retries three times and answers "Database temporarily unavailable", and an operator
-- reads that as a database outage instead of a schema gap. The two CREATE INDEX statements below fail for
-- the same reason, which is why this block has to come first.
--
-- ADD COLUMN IF NOT EXISTS is a no-op on a current database, so this costs a fresh install nothing.
-- Not covered here: a column that exists with the wrong TYPE (user_id was VARCHAR before it was BIGINT).
-- Widening a populated column is a data migration, not an idempotent DDL step, and is left to the operator.
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS category   VARCHAR(50);
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS user_id    BIGINT;
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS login      VARCHAR(200);
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS client_id  VARCHAR(200);
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS ip_address VARCHAR(50);
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS user_agent VARCHAR(500);
ALTER TABLE identity_audit_log ADD COLUMN IF NOT EXISTS details    TEXT;

-- Reconcile column TYPES that drifted.
--
-- Two columns changed type after the first release, and ADD COLUMN above cannot fix a column that is
-- already there. Both conversions are guarded on the current type, so they run at most once and cost a
-- current database nothing.
--
--   details: jsonb -> text. The dialect-agnostic parameter binding in IRedbContext.ExecuteAsync passes
--   strings; against a jsonb column Postgres refuses with "column is of type jsonb but expression is of
--   type text" and every audit write fails silently into the sink's error log.
--
--   user_id: varchar -> bigint. Converted only when every existing value is numeric; otherwise the table
--   is left alone and a notice is raised, because turning unparseable identifiers into NULL behind the
--   operator's back is a data loss they did not agree to.
DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns
         WHERE table_name = 'identity_audit_log' AND column_name = 'details') = 'jsonb' THEN
        ALTER TABLE identity_audit_log ALTER COLUMN details TYPE TEXT USING details::text;
        RAISE NOTICE 'identity_audit_log.details converted from jsonb to text';
    END IF;

    IF (SELECT data_type FROM information_schema.columns
         WHERE table_name = 'identity_audit_log' AND column_name = 'user_id') = 'character varying' THEN
        IF EXISTS (SELECT 1 FROM identity_audit_log
                    WHERE user_id IS NOT NULL AND user_id !~ '^[0-9]+$') THEN
            RAISE NOTICE 'identity_audit_log.user_id left as varchar: it holds non-numeric values. '
                         'Migrate them by hand — converting would silently null them out.';
        ELSE
            ALTER TABLE identity_audit_log
                ALTER COLUMN user_id TYPE BIGINT USING NULLIF(user_id, '')::bigint;
            RAISE NOTICE 'identity_audit_log.user_id converted from varchar to bigint';
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_audit_timestamp  ON identity_audit_log("timestamp");
CREATE INDEX IF NOT EXISTS ix_audit_event_type ON identity_audit_log(event_type);
CREATE INDEX IF NOT EXISTS ix_audit_category   ON identity_audit_log(category);
CREATE INDEX IF NOT EXISTS ix_audit_user_id    ON identity_audit_log(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_login      ON identity_audit_log(login);
