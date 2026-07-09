-- SQL Server partial unique indexes on _objects for Identity schemes.
--
-- NOTE — MSSQL column-type limitation:
--   _objects._value_string is NVARCHAR(MAX) which CANNOT be used as a key
--   column in a regular B-tree index. Therefore the three "_value_string"
--   based indexes that PostgreSQL provides for ClientId / Scope.Name /
--   OpenIddict ReferenceId are NOT created on MSSQL. Those three paths fall
--   back to the application-level check-then-save pattern, which leaves a
--   narrow TOCTOU window on multi-node deployments. See STATUS.md for the
--   cluster-correctness trade-off documentation.
--
--   The four indexes below cover the cases that MSSQL can enforce:
--     - MfaProps._key            (BIGINT)             — closes B1 race
--     - UserProps._key           (BIGINT)             — OIDC extension
--     - IdempotencyRecordProps._name  (NVARCHAR(450)) — HTTP idempotency
--     - IdempotentEntryProps._name    (NVARCHAR(450)) — route-level jti
--
-- Isolated per scheme via `WHERE _id_scheme = <scheme_id>`: the index is
-- scoped to one Identity scheme only and does NOT interfere with any user
-- Props extension attached to _users (or any other _objects row). Each block
-- looks the scheme up by its CLR FullName and silently skips if the scheme
-- has not yet been registered.
--
-- Reference script — the IdentityUniqueIndexesInitListener applies the same
-- indexes automatically at route-context startup. Execute this file manually
-- only if you want to bootstrap the indexes outside of the Identity module
-- lifecycle (e.g. DBA migration).

-- 1) MfaProps._key (userId — closes B1 recovery-code regeneration race) ---
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_identity_mfa_user_id')
BEGIN
    DECLARE @s1 BIGINT = (SELECT _id FROM _schemes WHERE _name = N'redb.Identity.Core.Models.MfaProps');
    IF @s1 IS NOT NULL
    BEGIN
        DECLARE @sql1 NVARCHAR(MAX) =
            N'CREATE UNIQUE INDEX [UX_identity_mfa_user_id] ' +
            N'ON [_objects]([_key]) ' +
            N'WHERE [_id_scheme] = ' + CAST(@s1 AS NVARCHAR(20)) + N' AND [_key] IS NOT NULL';
        EXEC sp_executesql @sql1;
    END
END
GO

-- 2) UserProps._key (userId — OIDC extension is one-per-user) --------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_identity_user_ext_user_id')
BEGIN
    DECLARE @s2 BIGINT = (SELECT _id FROM _schemes WHERE _name = N'redb.Identity.Core.Models.UserProps');
    IF @s2 IS NOT NULL
    BEGIN
        DECLARE @sql2 NVARCHAR(MAX) =
            N'CREATE UNIQUE INDEX [UX_identity_user_ext_user_id] ' +
            N'ON [_objects]([_key]) ' +
            N'WHERE [_id_scheme] = ' + CAST(@s2 AS NVARCHAR(20)) + N' AND [_key] IS NOT NULL';
        EXEC sp_executesql @sql2;
    END
END
GO

-- 3) IdempotencyRecordProps._name (HTTP Idempotency-Key composite) --------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_identity_idempotency_record_name')
BEGIN
    DECLARE @s3 BIGINT = (SELECT _id FROM _schemes WHERE _name = N'redb.Identity.Core.Models.IdempotencyRecordProps');
    IF @s3 IS NOT NULL
    BEGIN
        DECLARE @sql3 NVARCHAR(MAX) =
            N'CREATE UNIQUE INDEX [UX_identity_idempotency_record_name] ' +
            N'ON [_objects]([_name]) ' +
            N'WHERE [_id_scheme] = ' + CAST(@s3 AS NVARCHAR(20)) + N' AND [_name] IS NOT NULL';
        EXEC sp_executesql @sql3;
    END
END
GO

-- 4) IdempotentEntryProps._name (Route jti / message-key composite) -------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_route_idempotent_entry_name')
BEGIN
    DECLARE @s4 BIGINT = (SELECT _id FROM _schemes WHERE _name = N'redb.Route.RedbCore.Models.IdempotentEntryProps');
    IF @s4 IS NOT NULL
    BEGIN
        DECLARE @sql4 NVARCHAR(MAX) =
            N'CREATE UNIQUE INDEX [UX_route_idempotent_entry_name] ' +
            N'ON [_objects]([_name]) ' +
            N'WHERE [_id_scheme] = ' + CAST(@s4 AS NVARCHAR(20)) + N' AND [_name] IS NOT NULL';
        EXEC sp_executesql @sql4;
    END
END
GO
