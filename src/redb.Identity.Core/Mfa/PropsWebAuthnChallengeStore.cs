using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Mfa;

/// <summary>
/// MFA-3: PROPS-backed <see cref="IWebAuthnChallengeStore"/> mirroring
/// <see cref="PropsServerSideOtpStore"/>. Singleton; resolves <see cref="IRedbService"/>
/// through a fresh DI scope per operation to avoid captive-scope-in-singleton.
/// <para>
/// Anti-replay strategy: lookup-then-insert under transaction. The first
/// <see cref="ConsumeAsync"/> with a given challenge writes a
/// <see cref="WebAuthnConsumedChallengeProps"/> row; subsequent calls find the row and
/// return <see cref="WebAuthnConsumeResult.Replay"/>. The lookup-then-insert is run in a
/// transaction; if the underlying store were to allow concurrent inserts of the same
/// hash, we'd still have last-writer-wins on the row but both completes would proceed —
/// to make this race-tight, the calling code (e.g. <c>WebAuthnMfaMethod.CompleteAssert</c>)
/// is expected to run inside its own outer transaction with <c>LockForUpdateAsync</c> on
/// the user's <see cref="MfaProps"/> row, so two concurrent ceremonies for the same user
/// serialize on that lock before reaching here. Cross-user replay is ruled out by the
/// <c>UserId</c> check in <c>WebAuthnMfaMethod</c> — if attacker submits user A's challenge
/// against user B's account, the cross-check fails before we get here.
/// </para>
/// </summary>
public sealed class PropsWebAuthnChallengeStore : IWebAuthnChallengeStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PropsWebAuthnChallengeStore> _logger;
    private readonly TimeProvider _timeProvider;

    public PropsWebAuthnChallengeStore(
        IServiceScopeFactory scopeFactory,
        ILogger<PropsWebAuthnChallengeStore> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<WebAuthnConsumeResult> ConsumeAsync(
        byte[] challenge,
        long userId,
        string operation,
        TimeSpan ttl,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (challenge.Length == 0) throw new ArgumentException("Challenge cannot be empty", nameof(challenge));
        if (userId <= 0) throw new ArgumentOutOfRangeException(nameof(userId));
        ArgumentException.ThrowIfNullOrEmpty(operation);
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));

        var hash = ComputeSha256Hex(challenge);
        var now = _timeProvider.GetUtcNow();

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        await using var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false);

        var existing = await redb.Query<WebAuthnConsumedChallengeProps>()
            .Where(o => o.ChallengeHash == hash)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (existing is not null)
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            _logger.LogWarning(
                "WebAuthn challenge replay detected: hash={Hash} userId={UserId} operation={Op}",
                hash, userId, operation);
            return WebAuthnConsumeResult.Replay;
        }

        var row = new RedbObject<WebAuthnConsumedChallengeProps>(new WebAuthnConsumedChallengeProps
        {
            ChallengeHash = hash,
            UserId = userId,
            Operation = operation,
            ConsumedAt = now,
            ExpiresAt = now + ttl,
        });
        row.name = hash;

        await redb.SaveAsync(row).ConfigureAwait(false);
        await tx.CommitAsync().ConfigureAwait(false);
        return WebAuthnConsumeResult.Ok;
    }

    private static string ComputeSha256Hex(byte[] value)
    {
        var bytes = SHA256.HashData(value);
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
