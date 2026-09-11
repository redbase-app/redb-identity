using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Exceptions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.V4Unique;

/// <summary>
/// F3 of the V4-UNIQUE refactoring (doc/v4/03): Mfa/UserExt keyed by <c>[RedbUnique]</c>
/// UserId (owner decision R3a), SystemFlag and IdempotencyRecord keyed by <c>ValueUnique</c>
/// (R5v — SHA-256 of the composite). These are PARITY tests, not red-before: the pre-V4
/// artificial indexes on <c>_key</c>/<c>_name</c> existed on all three providers — F3 moves
/// the enforcement, it does not close a hole (unlike F1/F2).
/// </summary>
public sealed class V4UniqueUserKeysAndFlagsTests : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private readonly Xunit.Abstractions.ITestOutputHelper _out;

    public V4UniqueUserKeysAndFlagsTests(Xunit.Abstractions.ITestOutputHelper output) => _out = output;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var sc = new ServiceCollection();
        // Debug + xunit sink: the backfill listener swallows scheme-level failures into the
        // log by design, so a diagnosis needs its counters/errors visible in test output.
        sc.AddLogging(b => b.SetMinimumLevel(LogLevel.Debug).AddProvider(new XunitTestLoggerProvider(_out)));
        sc.AddRedbForTests(pgCs);
        _sp = sc.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        try { await redb.InitializeAsync(ensureCreated: true); }
        catch { await redb.InitializeAsync(); }
        await redb.SyncSchemeAsync<MfaProps>();
        await redb.SyncSchemeAsync<UserProps>();
        await redb.SyncSchemeAsync<IdentitySystemFlagProps>();
        await redb.SyncSchemeAsync<IdempotencyRecordProps>();
    }

    public async Task DisposeAsync() => await _sp.DisposeAsync();

    private static long UniqueUserId() => Random.Shared.NextInt64(1_000_000, long.MaxValue);

    [Fact]
    public async Task Duplicate_MfaUserId_IsRejected_SecondEnrollmentCannotForkTheState()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var userId = UniqueUserId();

        var first = new RedbObject<MfaProps>(new MfaProps { UserId = userId, Enabled = true });
        first.key = userId;
        await redb.SaveAsync(first);

        var second = new RedbObject<MfaProps>(new MfaProps { UserId = userId });
        second.key = userId;
        var act = async () => await redb.SaveAsync(second);
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "one MFA state per user — parity with the retired UX_identity_mfa_user_id index");

        var found = await redb.GetByUniqueAsync<MfaProps>(p => p.UserId, userId);
        found!.Props.Enabled.Should().BeTrue("the first (real) state is the one the key resolves to");
    }

    [Fact]
    public async Task Duplicate_UserExtUserId_IsRejected()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var userId = UniqueUserId();

        var first = new RedbObject<UserProps>(new UserProps { UserId = userId });
        first.key = userId;
        await redb.SaveAsync(first);

        var second = new RedbObject<UserProps>(new UserProps { UserId = userId });
        second.key = userId;
        var act = async () => await redb.SaveAsync(second);
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "one OIDC extension row per user — the advisory upsert paths rely on this");
    }

    [Fact]
    public async Task SystemFlag_FirstWins_SecondSetIsRejectedByValueUnique()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var flagName = $"v4-flag-{Guid.NewGuid():N}";

        var first = new RedbObject<IdentitySystemFlagProps>(new IdentitySystemFlagProps());
        first.Name = flagName;
        first.ValueUnique = flagName;
        first.value_bool = true;
        await redb.SaveAsync(first);

        var second = new RedbObject<IdentitySystemFlagProps>(new IdentitySystemFlagProps());
        second.Name = flagName;
        second.ValueUnique = flagName;
        second.value_bool = true;
        var act = async () => await redb.SaveAsync(second);
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "the one-shot flag is first-wins; SetBootstrapCompletedAsync catches exactly this "
            + "and treats it as already-completed");
    }

    [Fact]
    public async Task IdempotencyRecord_HashedValueUnique_RejectsDuplicates_AnyCompositeLength()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        // Composite far beyond the 440-char ValueUnique limit — the reason R5(v) hashes it.
        var longKey = new string('k', 300);
        var caller = new string('c', 200);
        var name = $"idem:test-scope:create:{caller}:{longKey}:{Guid.NewGuid():N}";
        name.Length.Should().BeGreaterThan(440, "the test must exercise the over-limit case");
        var hash = IdempotencyKeyHash.Sha256Hex(name);
        hash.Length.Should().Be(64, "SHA-256 hex always fits the 440-char ValueUnique");
        hash.Should().Be(IdempotencyKeyHash.Sha256Hex(name), "the hash is deterministic");

        var first = new RedbObject<IdempotencyRecordProps>(new IdempotencyRecordProps
        { Scope = "test-scope", Operation = "create" });
        first.name = name.Substring(0, 400); // readable copy, truncatable — not the key
        first.ValueUnique = hash;
        await redb.SaveAsync(first);

        var second = new RedbObject<IdempotencyRecordProps>(new IdempotencyRecordProps
        { Scope = "test-scope", Operation = "create" });
        second.name = name.Substring(0, 400);
        second.ValueUnique = hash;
        var act = async () => await redb.SaveAsync(second);
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "the capture race is resolved by the core ValueUnique index now, "
            + "parity with the retired UX_identity_idempotency_record_name");
    }

    [Fact]
    public async Task Backfill_RepairsKeyAndNameSchemes()
    {
        var userId = UniqueUserId();
        var flagName = $"v4-legacyflag-{Guid.NewGuid():N}";
        var idemName = $"idem:legacy:{Guid.NewGuid():N}";
        long mfaId;

        using (var scope = _sp.CreateScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

            // Legacy MfaProps: key set, Props.UserId absent (pre-V4 shape).
            var mfa = new RedbObject<MfaProps>(new MfaProps { Enabled = true });
            mfa.key = userId;
            mfaId = await redb.SaveAsync(mfa);

            // Legacy SystemFlag / IdempotencyRecord: _name only, no ValueUnique.
            var flag = new RedbObject<IdentitySystemFlagProps>(new IdentitySystemFlagProps());
            flag.Name = flagName;
            flag.value_bool = true;
            await redb.SaveAsync(flag);

            var rec = new RedbObject<IdempotencyRecordProps>(new IdempotencyRecordProps
            { Scope = "legacy" });
            rec.name = idemName;
            await redb.SaveAsync(rec);

            (await redb.GetByUniqueAsync<MfaProps>(p => p.UserId, userId)).Should().BeNull();
        }

        // Single-scheme gate-free passes — see V4UniqueKeyTests for why (parallel full
        // passes on the shared DB repaired each other's rows). Only the three schemes this
        // test seeds; UserProps stays untouched so the Duplicate_UserExt test's rows are
        // never repaired from under it.
        var listener = new V4UniqueBackfillListener(_sp);
        await listener.RunUserKeySchemeAsync<MfaProps>(
            p => p.UserId, (p, v) => p.UserId = v, CancellationToken.None);
        await listener.RunValueUniqueSchemeAsync<IdentitySystemFlagProps>(
            name => name, CancellationToken.None);
        await listener.RunValueUniqueSchemeAsync<IdempotencyRecordProps>(
            IdempotencyKeyHash.Sha256Hex, CancellationToken.None);

        using (var scope = _sp.CreateScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

            var mfa = await redb.GetByUniqueAsync<MfaProps>(p => p.UserId, userId);
            mfa.Should().NotBeNull("the backfill copied _key into Props.UserId");
            mfa!.Id.Should().Be(mfaId);

            var flag = await redb.Query<IdentitySystemFlagProps>()
                .WhereRedb(o => o.ValueUnique == flagName)
                .FirstOrDefaultAsync();
            flag.Should().NotBeNull("the backfill mirrored _name into ValueUnique");

            var rec = await redb.Query<IdempotencyRecordProps>()
                .WhereRedb(o => o.ValueUnique == IdempotencyKeyHash.Sha256Hex(idemName))
                .FirstOrDefaultAsync();
            rec.Should().NotBeNull("the backfill hashed _name into ValueUnique (R5v)");
        }
    }
}
