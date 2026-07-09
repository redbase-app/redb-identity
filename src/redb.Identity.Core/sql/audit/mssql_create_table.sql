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
