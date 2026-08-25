-- MSSQL DDL for identity audit log table.
-- Embedded resource — executed at module startup by
-- IdentityAuditLogTableInitListener via redb.Context.ExecuteAsync.
-- Idempotent (IF NOT EXISTS / OBJECT_ID checks).

IF OBJECT_ID('identity_audit_log', 'U') IS NULL
CREATE TABLE identity_audit_log (
    id           BIGINT IDENTITY(1,1) PRIMARY KEY,
    event_id     UNIQUEIDENTIFIER NOT NULL,
    event_type   NVARCHAR(100) NOT NULL,
    category     NVARCHAR(50),
    [timestamp]  DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    user_id      BIGINT,
    login        NVARCHAR(200),
    client_id    NVARCHAR(200),
    ip_address   NVARCHAR(50),
    user_agent   NVARCHAR(500),
    details      NVARCHAR(MAX),
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);

-- Reconcile an existing table.
--
-- The OBJECT_ID guard above skips the CREATE entirely when the table is already there, so a database
-- created before a column existed never gains it — and nothing says so. The audit query selects
-- `category` and `login`; without them it fails, the route's DbException handler retries and answers
-- "Database temporarily unavailable", and an operator reads a schema gap as a database outage. The index
-- statements below fail for the same reason, which is why this block comes first.
--
-- Each check is a no-op on a current database. Not covered: a column that exists with the wrong TYPE
-- (user_id was VARCHAR before it was BIGINT) — that is a data migration, not idempotent DDL.
IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'category')
    ALTER TABLE identity_audit_log ADD category NVARCHAR(50);

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'user_id')
    ALTER TABLE identity_audit_log ADD user_id BIGINT;

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'login')
    ALTER TABLE identity_audit_log ADD login NVARCHAR(200);

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'client_id')
    ALTER TABLE identity_audit_log ADD client_id NVARCHAR(200);

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'ip_address')
    ALTER TABLE identity_audit_log ADD ip_address NVARCHAR(50);

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'user_agent')
    ALTER TABLE identity_audit_log ADD user_agent NVARCHAR(500);

IF NOT EXISTS (SELECT 1 FROM sys.columns
               WHERE object_id = OBJECT_ID('identity_audit_log') AND name = 'details')
    ALTER TABLE identity_audit_log ADD details NVARCHAR(MAX);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_audit_timestamp')
    CREATE INDEX ix_audit_timestamp  ON identity_audit_log([timestamp]);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_audit_event_type')
    CREATE INDEX ix_audit_event_type ON identity_audit_log(event_type);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_audit_category')
    CREATE INDEX ix_audit_category   ON identity_audit_log(category);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_audit_user_id')
    CREATE INDEX ix_audit_user_id    ON identity_audit_log(user_id);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_audit_login')
    CREATE INDEX ix_audit_login      ON identity_audit_log(login);
