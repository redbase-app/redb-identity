using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;

namespace redb.Identity.Core.PasswordReset;

/// <summary>
/// N-4 (Session C): redb-backed <see cref="IPasswordResetTokenStore"/>. Singleton; resolves
/// <see cref="IRedbService"/> through a fresh DI scope per operation (identical pattern to
/// <c>PropsServerSideOtpStore</c> / <c>PropsSigningKeyStore</c>) to avoid captive-scope-in-singleton.
/// <para>
/// Tokens are 32 bytes of CSPRNG, base64url-encoded (no padding). Only the peppered
/// SHA-256 hex of the plaintext is persisted (<see cref="PasswordResetTokenProps.TokenHash"/>);
/// the plaintext is returned to the caller exactly once for e-mail delivery.
/// </para>
/// <para>
/// Verify runs inside a redb transaction + <c>LockForUpdateAsync</c> on the token row so
/// concurrent verify calls against the same <c>jti</c> serialize cleanly — the first
/// successful call flips <see cref="PasswordResetTokenProps.Consumed"/>, subsequent calls
/// see the flag under the lock and return <see cref="PasswordResetVerifyResult"/> with
/// <c>Reason = already_consumed</c>.
/// </para>
/// </summary>
public sealed class RedbPasswordResetTokenStore : IPasswordResetTokenStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly RecoveryCodePepperProvider _pepperProvider;
    private readonly ILogger<RedbPasswordResetTokenStore> _logger;
    private readonly TimeProvider _timeProvider;

    public RedbPasswordResetTokenStore(
        IServiceScopeFactory scopeFactory,
        RecoveryCodePepperProvider pepperProvider,
        ILogger<RedbPasswordResetTokenStore> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _pepperProvider = pepperProvider ?? throw new ArgumentNullException(nameof(pepperProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<PasswordResetIssueResult> IssueAsync(
        long userId,
        string callerResetUrl,
        TimeSpan ttl,
        CancellationToken ct = default)
    {
        if (userId <= 0) throw new ArgumentOutOfRangeException(nameof(userId));
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));

        var jti = Guid.NewGuid();
        var token = GenerateToken();
        var now = _timeProvider.GetUtcNow();
        var expires = now + ttl;
        var hash = ComputePepperedSha256Hex(token);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var obj = new RedbObject<PasswordResetTokenProps>(new PasswordResetTokenProps
        {
            Jti = jti.ToString("N"),
            UserId = userId,
            TokenHash = hash,
            IssuedAt = now,
            ExpiresAt = expires,
            Consumed = false,
            Attempts = 0,
            CallerResetUrl = callerResetUrl ?? string.Empty,
        });
        obj.name = jti.ToString("N");

        await redb.SaveAsync(obj).ConfigureAwait(false);
        return new PasswordResetIssueResult(jti, token, expires);
    }

    /// <inheritdoc />
    public async Task<PasswordResetVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        string token,
        CancellationToken ct = default)
    {
        if (jti == Guid.Empty) return new PasswordResetVerifyResult(false, 0, "not_found");
        if (string.IsNullOrEmpty(token)) return new PasswordResetVerifyResult(false, 0, "bad_token");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var key = jti.ToString("N");
        await using var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false);

        var row = await redb.Query<PasswordResetTokenProps>()
            .Where(o => o.Jti == key)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (row is null)
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            return new PasswordResetVerifyResult(false, 0, "not_found");
        }

        // Serialize concurrent verify attempts against the same row.
        if (row.key.HasValue)
            await redb.LockForUpdateAsync(row.key.Value).ConfigureAwait(false);

        var p = row.Props;
        var now = _timeProvider.GetUtcNow();

        if (p.Consumed)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new PasswordResetVerifyResult(false, 0, "already_consumed");
        }
        if (p.ExpiresAt < now)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new PasswordResetVerifyResult(false, 0, "expired");
        }

        var candidate = ComputePepperedSha256Hex(token.Trim());
        var ok = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(candidate),
            Encoding.ASCII.GetBytes(p.TokenHash));

        p.Attempts++;
        if (ok)
        {
            p.Consumed = true;
        }

        try
        {
            await redb.SaveAsync(row).ConfigureAwait(false);
            await tx.CommitAsync().ConfigureAwait(false);
        }
        catch
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            throw;
        }

        return ok
            ? new PasswordResetVerifyResult(true, p.UserId, "ok")
            : new PasswordResetVerifyResult(false, 0, "bad_token");
    }

    private static string GenerateToken()
    {
        // 32 bytes CSPRNG → base64url (no padding). ~43 chars; comfortably > 128 bits of entropy.
        Span<byte> buf = stackalloc byte[32];
        RandomNumberGenerator.Fill(buf);
        return Base64UrlEncode(buf);
    }

    private string ComputePepperedSha256Hex(string token)
    {
        var pepper = _pepperProvider.Pepper;
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var input = new byte[pepper.Length + tokenBytes.Length];
        Buffer.BlockCopy(pepper, 0, input, 0, pepper.Length);
        Buffer.BlockCopy(tokenBytes, 0, input, pepper.Length, tokenBytes.Length);
        var bytes = SHA256.HashData(input);
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        var s = Convert.ToBase64String(bytes);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
