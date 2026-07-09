-- SQLite partial unique indexes on _objects for Identity schemes.
--
-- Purpose: close TOCTOU races in ApplicationManagementProcessor,
-- ScopeManagementProcessor, IdempotencyProcessor, MfaService and user-profile
-- upsert paths where a check-then-save pattern was relied upon.
--
-- Isolated per scheme via `WHERE _id_scheme = <scheme_id>`: the index is scoped
-- to one Identity scheme only and does NOT interfere with any user Props
-- extension attached to _users (or any other _objects row).
--
-- SQLite specifics:
--   * Partial unique indexes are supported since SQLite 3.8.0 (Aug 2013).
--   * SQLite has no NVARCHAR(MAX) restriction — _value_string is TEXT and
--     fits in a B-tree key without trade-offs, so all seven indexes apply
--     here (vs PostgreSQL six + MSSQL four — see the per-listener log line
--     in IdentityUniqueIndexesInitListener).
--   * Identifiers can be safely double-quoted; scheme_id is inlined as a
--     literal because SQLite (like Postgres) does not accept bound
--     parameters in WHERE clauses on CREATE INDEX statements.
--
-- Reference script — the IdentityUniqueIndexesInitListener applies the same
-- indexes automatically at route-context startup. Execute this file manually
-- only if you want to bootstrap the indexes outside of the Identity module
-- lifecycle. The scheme-id literals below are placeholders ({SchemeId}) and
-- must be substituted with real ids from `_schemes` before running.

-- 1) ApplicationProps._value_string (OAuth ClientId)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_application_client_id"
    ON _objects (_value_string)
    WHERE _id_scheme = {ApplicationPropsId} AND _value_string IS NOT NULL;

-- 2) ScopeProps._value_string (Scope.Name)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_scope_name"
    ON _objects (_value_string)
    WHERE _id_scheme = {ScopePropsId} AND _value_string IS NOT NULL;

-- 3) TokenProps._value_string (OpenIddict ReferenceId)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_token_reference_id"
    ON _objects (_value_string)
    WHERE _id_scheme = {TokenPropsId} AND _value_string IS NOT NULL;

-- 4) MfaProps._key (userId — closes B1 recovery-code regeneration race)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_mfa_user_id"
    ON _objects (_key)
    WHERE _id_scheme = {MfaPropsId} AND _key IS NOT NULL;

-- 5) UserProps._key (userId — OIDC extension is one-per-user)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_user_ext_user_id"
    ON _objects (_key)
    WHERE _id_scheme = {UserPropsId} AND _key IS NOT NULL;

-- 6) IdempotencyRecordProps._name (HTTP Idempotency-Key composite)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_idempotency_record_name"
    ON _objects (_name)
    WHERE _id_scheme = {IdempotencyRecordPropsId} AND _name IS NOT NULL;

-- 7) IdempotentEntryProps._name (Route jti / message-key composite)
CREATE UNIQUE INDEX IF NOT EXISTS "UX_route_idempotent_entry_name"
    ON _objects (_name)
    WHERE _id_scheme = {IdempotentEntryPropsId} AND _name IS NOT NULL;

-- 8) IdentitySystemFlagProps._name (B1 bootstrap / system flag — UNIQUE per
--    flag id ("bootstrap_completed", future flags).
CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_system_flag_name"
    ON _objects (_name)
    WHERE _id_scheme = {IdentitySystemFlagPropsId} AND _name IS NOT NULL;
