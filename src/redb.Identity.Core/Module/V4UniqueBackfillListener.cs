using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Exceptions;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// V4-UNIQUE transition backfill (doc/v4/04, §3). Pre-V4 the unique keys of Identity schemes
/// lived only in the <c>_objects.value_string</c> mirror while the Props property was a
/// <c>[RedbIgnore]</c> phantom — so existing rows have NO <c>_values</c> value and therefore
/// no <c>_unique</c> hash, and the new <c>GetByUniqueAsync</c> lookups cannot see them.
/// This listener copies the mirror into Props and re-saves, which computes the unique key.
///
/// <para>
/// Idempotent by construction, no completion flag: a repaired row drops out of the candidate
/// set (Props value equals the mirror), so a re-run converges to a no-op. Candidates are rows
/// with a non-NULL mirror; after teardown (doc/v4/04 §4) new rows stop carrying the mirror,
/// so the set shrinks to legacy rows only and empties as they are re-saved or TTL-reaped.
/// </para>
///
/// <para>
/// A duplicate discovered during backfill (possible for the schemes that never actually had
/// an index — ClaimScope, FederatedIdentity, FederationProvider) surfaces as
/// <see cref="RedbUniqueViolationException"/>: per owner decision R4(a) it is logged with both
/// ids and the loser keeps a NULL key (outside the index) for manual review. Federated-link
/// duplicates are logged as errors — two users holding one external identity is a potential
/// account-takeover and must reach the operator.
/// </para>
///
/// Registered in <see cref="InitRoute"/> after <see cref="IdentityUniqueIndexesInitListener"/>
/// (schemes exist) and BEFORE the seed listeners — the seeds look up by unique key now, and
/// must see legacy seeded rows as repaired, not recreate them.
/// </summary>
internal sealed class V4UniqueBackfillListener : IRouteLifecycleListener
{
    /// <summary>
    /// Convergence flag (critical-review finding, doc/v4/00 §12): without it every boot
    /// re-loads every candidate row of every scheme — all user-ext rows included — for ever.
    /// Once one boot has backfilled every scheme clean and dropped the retired indexes, this
    /// SystemFlag row short-circuits all later boots. Versioned name: bump the suffix if
    /// schemes are ever added to this listener. Delete the row to force a re-run.
    /// </summary>
    internal const string ConvergedFlagName = "v4_unique_backfill_done:v1";

    private readonly IServiceProvider _sp;

    public V4UniqueBackfillListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<V4UniqueBackfillListener>();

        try
        {
            var converged = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.ValueUnique == ConvergedFlagName)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            if (converged is not null)
            {
                logger.LogDebug("V4-UNIQUE backfill: already converged, skipping.");
                return;
            }
        }
        catch (Exception ex)
        {
            // A failed probe (fresh database, scheme not there yet) just means running the
            // idempotent pass below.
            logger.LogDebug(ex, "V4-UNIQUE backfill: convergence probe failed; running the pass.");
        }

        await RunPassIgnoringConvergenceAsync(scope.ServiceProvider, redb, logger, ct).ConfigureAwait(false);
    }

    // ── Test seams (V4Unique backfill tests): repair EXACTLY ONE scheme ─────────────
    // On the process-shared SQLite database the test classes run in parallel; a full
    // gate-free pass from one class also repairs the other classes' freshly-created
    // legacy rows, and two concurrent full passes over the same row produced
    // false-duplicate unique collisions and stale-snapshot overwrites (the
    // ordering-dependent failures of 2026-09-08). A single-scheme pass touches only the
    // calling test's rows; the full pass stays private to the production gate above.

    internal Task<bool> RunMirrorSchemeAsync<TProps>(
        Func<TProps, string?> getKey, Action<TProps, string?> setKey, CancellationToken ct)
        where TProps : class, new()
        => RunOneAsync((redb, logger) => BackfillMirrorAsync<TProps>(redb, logger, getKey, setKey, ct));

    internal Task<bool> RunUserKeySchemeAsync<TProps>(
        Func<TProps, long?> getKey, Action<TProps, long?> setKey, CancellationToken ct)
        where TProps : class, new()
        => RunOneAsync((redb, logger) => BackfillUserKeyAsync<TProps>(redb, logger, getKey, setKey, ct));

    internal Task<bool> RunValueUniqueSchemeAsync<TProps>(
        Func<string, string> transform, CancellationToken ct)
        where TProps : class, new()
        => RunOneAsync((redb, logger) => BackfillValueUniqueAsync<TProps>(redb, logger, transform, ct));

    private async Task<bool> RunOneAsync(Func<IRedbService, ILogger, Task<bool>> pass)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<V4UniqueBackfillListener>();
        return await pass(redb, logger).ConfigureAwait(false);
    }

    private async Task RunPassIgnoringConvergenceAsync(
        IServiceProvider scopedSp, IRedbService redb, ILogger logger, CancellationToken ct)
    {
        var clean = true;

        // F1 schemes: key was mirrored in value_string, Props was the [RedbIgnore] phantom.
        clean &= await BackfillMirrorAsync<ApplicationProps>(redb, logger,
            p => p.ClientId, (p, v) => p.ClientId = v, ct).ConfigureAwait(false);
        clean &= await BackfillMirrorAsync<ScopeProps>(redb, logger,
            p => p.ScopeName, (p, v) => p.ScopeName = v, ct).ConfigureAwait(false);
        clean &= await BackfillMirrorAsync<ClaimScopeProps>(redb, logger,
            p => p.ScopeName, (p, v) => p.ScopeName = v, ct).ConfigureAwait(false);
        clean &= await BackfillMirrorAsync<TokenProps>(redb, logger,
            p => p.ReferenceId, (p, v) => p.ReferenceId = v, ct).ConfigureAwait(false);

        // F2 schemes (doc/v4/02): these two never actually had an index, so this is the
        // first time their keys become enforceable — duplicates are EXPECTED to be possible
        // here and every one is a finding for the operator (a duplicated federated link is
        // a potential account-takeover vector, see the class doc).
        clean &= await BackfillMirrorAsync<FederatedIdentityProps>(redb, logger,
            p => p.LinkKey, (p, v) => p.LinkKey = v, ct).ConfigureAwait(false);
        clean &= await BackfillMirrorAsync<FederationProviderProps>(redb, logger,
            p => p.ProviderId is { Length: > 0 } pid ? pid : null,
            (p, v) => p.ProviderId = v ?? string.Empty, ct).ConfigureAwait(false);

        // F3 key-mirror schemes (doc/v4/03): the key is the numeric _objects._key, copied
        // into the [RedbUnique] UserId prop.
        clean &= await BackfillUserKeyAsync<MfaProps>(redb, logger,
            p => p.UserId, (p, v) => p.UserId = v, ct).ConfigureAwait(false);
        clean &= await BackfillUserKeyAsync<UserProps>(redb, logger,
            p => p.UserId, (p, v) => p.UserId = v, ct).ConfigureAwait(false);

        // F3 ValueUnique schemes (doc/v4/03): the key is the root _name (SystemFlag) or its
        // SHA-256 (IdempotencyRecord, owner decision R5(v)); Props are not touched.
        clean &= await BackfillValueUniqueAsync<IdentitySystemFlagProps>(redb, logger,
            name => name, ct).ConfigureAwait(false);
        clean &= await BackfillValueUniqueAsync<IdempotencyRecordProps>(redb, logger,
            Routes.Processors.IdempotencyKeyHash.Sha256Hex, ct).ConfigureAwait(false);

        // ── Teardown (doc/v4/04 §3 step 5): drop the retired pre-V4 indexes — but only
        // after EVERY scheme backfilled without a scheme-level failure. A failed scheme
        // keeps the old indexes one more boot (idempotent retry) so its rows are never
        // left without either enforcement. Duplicate findings do NOT block the drop:
        // dropping an index that never guarded those schemes changes nothing for them.
        if (clean)
        {
            await DropRetiredIndexesAsync(scopedSp, redb, logger).ConfigureAwait(false);

            // Mark convergence — first-wins across racing nodes.
            try
            {
                var flag = new RedbObject<IdentitySystemFlagProps>(new IdentitySystemFlagProps());
                flag.Name = ConvergedFlagName;
                flag.ValueUnique = ConvergedFlagName;
                flag.value_bool = true;
                flag.value_datetime = DateTime.UtcNow;
                flag.note = "V4-UNIQUE transition backfill converged; the listener now no-ops. "
                          + "Delete this row to force a re-run (doc/v4/04 §3).";
                await redb.SaveAsync(flag).ConfigureAwait(false);
            }
            catch (RedbUniqueViolationException)
            {
                // Another node converged concurrently — same outcome.
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "V4-UNIQUE: converged, but the flag row could not be written; the (idempotent) "
                    + "pass will re-run on the next boot.");
            }
        }
        else
        {
            logger.LogWarning(
                "V4-UNIQUE: at least one scheme's backfill failed — the retired pre-V4 indexes are "
                + "kept for this boot and the whole pass retries on the next start.");
        }
    }

    /// <summary>The pre-V4 indexes replaced by core primitives (doc/v4/04 §2). Only
    /// UX_users_email stays (owner decision R1). UX_route_idempotent_entry_name joined the
    /// retired set on 2026-09-02, when Route's own fix (816a3d2a) shipped ValueUnique + the
    /// typed catch in RedbIdempotentRepository.</summary>
    private static readonly string[] RetiredIndexes =
    [
        "UX_identity_application_client_id",
        "UX_identity_scope_name",
        "UX_identity_token_reference_id",
        "UX_identity_mfa_user_id",
        "UX_identity_user_ext_user_id",
        "UX_identity_idempotency_record_name",
        "UX_identity_system_flag_name",
        "UX_route_idempotent_entry_name",
    ];

    private static async Task DropRetiredIndexesAsync(
        IServiceProvider scopedSp, IRedbService redb, ILogger logger)
    {
        var dialect = scopedSp.GetRequiredService<ISqlDialect>();
        var isMsSql = string.Equals(dialect.ProviderName, "MSSql", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(dialect.ProviderName, "SqlServer", StringComparison.OrdinalIgnoreCase);

        foreach (var name in RetiredIndexes)
        {
            var sql = isMsSql
                ? $"IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = '{name}') DROP INDEX [{name}] ON [_objects]"
                : $"DROP INDEX IF EXISTS \"{name}\"";
            try
            {
                await redb.Context.ExecuteAsync(sql).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // A role without DDL rights degrades to a leftover (harmless) index; hand the
                // operator the exact statement instead of failing the boot — same contract the
                // index CREATION always had.
                logger.LogError(ex,
                    "V4-UNIQUE: could not drop retired index '{Index}'. Run manually: {Sql}", name, sql);
            }
        }
        logger.LogInformation("V4-UNIQUE: retired pre-V4 unique indexes dropped (idempotent).");
    }

    /// <summary>
    /// F3 variant of <see cref="BackfillMirrorAsync{TProps}"/>: the pre-V4 key lives in the
    /// numeric <c>_objects._key</c> (MfaProps, UserProps ext), copied into the
    /// <c>[RedbUnique]</c> UserId prop. Same idempotence-by-construction: a repaired row
    /// (Props.UserId == key) drops out.
    /// </summary>
    private static async Task<bool> BackfillUserKeyAsync<TProps>(
        IRedbService redb,
        ILogger logger,
        Func<TProps, long?> getKey,
        Action<TProps, long?> setKey,
        CancellationToken ct)
        where TProps : class, new()
    {
        try
        {
            await redb.SyncSchemeAsync<TProps>().ConfigureAwait(false);

            var candidates = await redb.Query<TProps>()
                .WhereRedb(o => o.Key != null)
                .ToListAsync()
                .ConfigureAwait(false);

            var repaired = 0;
            var duplicates = 0;
            foreach (var obj in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (obj.key is not { } key || getKey(obj.Props) == key)
                    continue;

                setKey(obj.Props, key);
                try
                {
                    await redb.SaveAsync(obj).ConfigureAwait(false);
                    repaired++;
                }
                catch (RedbUniqueViolationException ex)
                {
                    duplicates++;
                    logger.LogError(ex,
                        "V4-UNIQUE backfill: DUPLICATE user key {Key} in {Scheme} — object {Id} keeps a NULL "
                        + "unique key (outside the index) and needs manual review.",
                        key, typeof(TProps).Name, obj.id);
                }
            }

            if (repaired > 0 || duplicates > 0)
                logger.LogInformation(
                    "V4-UNIQUE backfill {Scheme}: candidates={Candidates} repaired={Repaired} duplicates={Duplicates}",
                    typeof(TProps).Name, candidates.Count, repaired, duplicates);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "V4-UNIQUE backfill failed for {Scheme}.", typeof(TProps).Name);
            return false;
        }
    }

    /// <summary>
    /// F3 variant for root-only schemes: the pre-V4 key lives in <c>_objects._name</c> and the
    /// enforced key is <c>ValueUnique = transform(_name)</c> (identity for SystemFlag, SHA-256
    /// for IdempotencyRecord). Props are never touched — SystemFlag has none by design.
    /// </summary>
    private static async Task<bool> BackfillValueUniqueAsync<TProps>(
        IRedbService redb,
        ILogger logger,
        Func<string, string> transform,
        CancellationToken ct)
        where TProps : class, new()
    {
        try
        {
            await redb.SyncSchemeAsync<TProps>().ConfigureAwait(false);

            var candidates = await redb.Query<TProps>()
                .WhereRedb(o => o.Name != null)
                .ToListAsync()
                .ConfigureAwait(false);

            var repaired = 0;
            var duplicates = 0;
            foreach (var obj in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (obj.name is not { } name || obj.ValueUnique is not null)
                    continue;

                obj.ValueUnique = transform(name);
                try
                {
                    await redb.SaveAsync(obj).ConfigureAwait(false);
                    repaired++;
                }
                catch (RedbUniqueViolationException ex)
                {
                    duplicates++;
                    logger.LogError(ex,
                        "V4-UNIQUE backfill: DUPLICATE root key '{Name}' in {Scheme} — object {Id} keeps a NULL "
                        + "ValueUnique (outside the index) and needs manual review.",
                        name, typeof(TProps).Name, obj.id);
                }
            }

            if (repaired > 0 || duplicates > 0)
                logger.LogInformation(
                    "V4-UNIQUE backfill {Scheme}: candidates={Candidates} repaired={Repaired} duplicates={Duplicates}",
                    typeof(TProps).Name, candidates.Count, repaired, duplicates);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "V4-UNIQUE backfill failed for {Scheme}.", typeof(TProps).Name);
            return false;
        }
    }

    /// <summary>
    /// Repairs one scheme: every row whose <c>value_string</c> mirror is set but whose Props
    /// key does not match gets the mirror copied into Props and is re-saved (the save computes
    /// the <c>_unique</c> hash). The candidate query is by the indexed base field; the
    /// props-vs-mirror comparison is in memory on purpose — a legacy row has no
    /// <c>_values</c> row at all, and a server-side <c>Props == null</c> filter would have to
    /// distinguish "value IS NULL" from "no row", which this code must not depend on.
    /// </summary>
    private static async Task<bool> BackfillMirrorAsync<TProps>(
        IRedbService redb,
        ILogger logger,
        Func<TProps, string?> getKey,
        Action<TProps, string?> setKey,
        CancellationToken ct)
        where TProps : class, new()
    {
        try
        {
            await redb.SyncSchemeAsync<TProps>().ConfigureAwait(false);

            var candidates = await redb.Query<TProps>()
                .WhereRedb(o => o.ValueString != null)
                .ToListAsync()
                .ConfigureAwait(false);

            var repaired = 0;
            var duplicates = 0;
            foreach (var obj in candidates)
            {
                ct.ThrowIfCancellationRequested();
                var mirror = obj.value_string;
                if (mirror is null || getKey(obj.Props) == mirror)
                    continue; // already repaired (or a fresh dual-write row)

                setKey(obj.Props, mirror);
                try
                {
                    await redb.SaveAsync(obj).ConfigureAwait(false);
                    repaired++;
                }
                catch (RedbUniqueViolationException ex)
                {
                    duplicates++;
                    // R4(a): report, leave the loser outside the index, keep going.
                    // The prop value at the moment of failure is logged next to the mirror: when the two
                    // agree the value was intact and the rejected key was computed wrongly; when they
                    // differ the object carried another object's value (2026-09-10 MSSQL full-run triage).
                    logger.LogError(ex,
                        "V4-UNIQUE backfill: DUPLICATE key '{Key}' in {Scheme} — object {Id} keeps a NULL "
                        + "unique key (outside the index) and needs manual review. Prop value at failure: '{PropValue}'.",
                        mirror, typeof(TProps).Name, obj.id, getKey(obj.Props));
                }
            }

            if (repaired > 0 || duplicates > 0)
                logger.LogInformation(
                    "V4-UNIQUE backfill {Scheme}: candidates={Candidates} repaired={Repaired} duplicates={Duplicates}",
                    typeof(TProps).Name, candidates.Count, repaired, duplicates);
            return true;
        }
        catch (Exception ex)
        {
            // Do not abort the bootstrap: an unfilled scheme degrades to "legacy rows invisible
            // to unique lookups" — visible and diagnosable — rather than a dead host.
            logger.LogError(ex, "V4-UNIQUE backfill failed for {Scheme}.", typeof(TProps).Name);
            return false;
        }
    }
}
