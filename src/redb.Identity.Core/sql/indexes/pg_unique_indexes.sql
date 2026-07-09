-- PostgreSQL partial unique indexes on _objects for Identity schemes.
--
-- Purpose: close TOCTOU races in ApplicationManagementProcessor,
-- ScopeManagementProcessor, IdempotencyProcessor, MfaService and user-profile
-- upsert paths where a check-then-save pattern was relied upon.
--
-- Isolated per scheme via `WHERE _id_scheme = <scheme_id>`: the index is scoped
-- to one Identity scheme only and does NOT interfere with any user Props
-- extension attached to _users (or any other _objects row). Each DO block looks
-- the scheme up by its CLR FullName and silently skips if the scheme has not
-- yet been registered (e.g. during a partial bootstrap).
--
-- Reference script — the IdentityUniqueIndexesInitListener applies the same
-- indexes automatically at route-context startup. Execute this file manually
-- only if you want to bootstrap the indexes outside of the Identity module
-- lifecycle (e.g. DBA migration, read-replica maintenance).
--
-- DDL is idempotent (IF NOT EXISTS); safe to re-run on existing databases.

-- 1) ApplicationProps._value_string (OAuth ClientId) -----------------------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.ApplicationProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_application_client_id" '
            'ON _objects (_value_string) '
            'WHERE _id_scheme = %s AND _value_string IS NOT NULL',
            s);
    END IF;
END $$;

-- 2) ScopeProps._value_string (Scope.Name) --------------------------------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.ScopeProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_scope_name" '
            'ON _objects (_value_string) '
            'WHERE _id_scheme = %s AND _value_string IS NOT NULL',
            s);
    END IF;
END $$;

-- 3) TokenProps._value_string (OpenIddict ReferenceId) --------------------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.TokenProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_token_reference_id" '
            'ON _objects (_value_string) '
            'WHERE _id_scheme = %s AND _value_string IS NOT NULL',
            s);
    END IF;
END $$;

-- 4) MfaProps._key (userId — closes B1 recovery-code regeneration race) ---
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.MfaProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_mfa_user_id" '
            'ON _objects (_key) '
            'WHERE _id_scheme = %s AND _key IS NOT NULL',
            s);
    END IF;
END $$;

-- 5) UserProps._key (userId — OIDC extension is one-per-user) --------------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.UserProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_user_ext_user_id" '
            'ON _objects (_key) '
            'WHERE _id_scheme = %s AND _key IS NOT NULL',
            s);
    END IF;
END $$;

-- 6) IdempotencyRecordProps._name (HTTP Idempotency-Key composite) --------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Identity.Core.Models.IdempotencyRecordProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_identity_idempotency_record_name" '
            'ON _objects (_name) '
            'WHERE _id_scheme = %s AND _name IS NOT NULL',
            s);
    END IF;
END $$;

-- 7) IdempotentEntryProps._name (Route jti / message-key composite) -------
DO $$
DECLARE s bigint;
BEGIN
    SELECT _id INTO s FROM _schemes WHERE _name = 'redb.Route.RedbCore.Models.IdempotentEntryProps';
    IF s IS NOT NULL THEN
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS "UX_route_idempotent_entry_name" '
            'ON _objects (_name) '
            'WHERE _id_scheme = %s AND _name IS NOT NULL',
            s);
    END IF;
END $$;
