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

namespace redb.Identity.Core.Mfa;

/// <summary>
/// B3: PROPS-backed <see cref="IServerSideOtpStore"/>. Singleton; resolves
/// <see cref="IRedbService"/> through a fresh DI scope per operation (identical pattern to
/// <c>PropsSigningKeyStore</c> / <c>RedbXmlRepository</c>) to avoid captive-scope-in-singleton.
/// <para>
/// Codes are 6 ASCII digits generated via <see cref="RandomNumberGenerator"/>. Only the
/// SHA-256 hex of the plaintext is persisted (<see cref="MfaOtpProps.CodeHash"/>); the
/// plaintext is returned to the caller exactly once for channel delivery.
/// </para>
/// <para>
/// Verify runs inside a redb transaction + <c>LockForUpdateAsync</c> on the OTP row so
/// concurrent verify calls against the same <c>jti</c> serialize cleanly — the first
/// successful call flips <see cref="MfaOtpProps.Consumed"/>, subsequent calls see the flag
/// under the lock and return <see cref="OtpVerifyResult"/> with
/// <c>Reason = already_consumed</c>.
/// </para>
/// </summary>
public sealed class PropsServerSideOtpStore : IServerSideOtpStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PropsServerSideOtpStore> _logger;
    private readonly TimeProvider _timeProvider;

    public PropsServerSideOtpStore(
        IServiceScopeFactory scopeFactory,
        ILogger<PropsServerSideOtpStore> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<OtpIssueResult> IssueAsync(
        long userId,
        string method,
        string destinationMasked,
        TimeSpan ttl,
        CancellationToken ct = default)
    {
        if (userId <= 0) throw new ArgumentOutOfRangeException(nameof(userId));
        ArgumentException.ThrowIfNullOrEmpty(method);
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));

        var jti = Guid.NewGuid();
        var code = GenerateOtpCode();
        var now = _timeProvider.GetUtcNow();
        var expires = now + ttl;
        var hash = ComputeSha256Hex(code);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var obj = new RedbObject<MfaOtpProps>(new MfaOtpProps
        {
            Jti = jti.ToString("N"),
            UserId = userId,
            Method = method,
            CodeHash = hash,
            DestinationMasked = destinationMasked ?? string.Empty,
            IssuedAt = now,
            ExpiresAt = expires,
            Consumed = false,
            Attempts = 0,
        });
        obj.name = jti.ToString("N");

        await redb.SaveAsync(obj).ConfigureAwait(false);
        return new OtpIssueResult(jti, code, destinationMasked ?? string.Empty, expires);
    }

    /// <inheritdoc />
    public async Task<OtpVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        long userId,
        string code,
        CancellationToken ct = default)
    {
        if (jti == Guid.Empty) return new OtpVerifyResult(false, "not_found");
        if (string.IsNullOrEmpty(code)) return new OtpVerifyResult(false, "bad_code");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var key = jti.ToString("N");
        await using var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false);

        var row = await redb.Query<MfaOtpProps>()
            .Where(o => o.Jti == key)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (row is null)
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            return new OtpVerifyResult(false, "not_found");
        }

        // Serialize concurrent verify attempts against the same row.
        if (row.key.HasValue)
            await redb.LockForUpdateAsync(row.key.Value).ConfigureAwait(false);

        var p = row.Props;

        if (p.UserId != userId)
        {
            p.Attempts++;
            try { await redb.SaveAsync(row).ConfigureAwait(false); await tx.CommitAsync().ConfigureAwait(false); }
            catch { await tx.RollbackAsync().ConfigureAwait(false); throw; }
            return new OtpVerifyResult(false, "user_mismatch", p.Method);
        }

        var now = _timeProvider.GetUtcNow();
        if (p.Consumed)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new OtpVerifyResult(false, "already_consumed", p.Method);
        }
        if (p.ExpiresAt < now)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new OtpVerifyResult(false, "expired", p.Method);
        }

        var candidate = ComputeSha256Hex(code.Trim());
        var ok = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(candidate),
            Encoding.ASCII.GetBytes(p.CodeHash));

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
            ? new OtpVerifyResult(true, "ok", p.Method)
            : new OtpVerifyResult(false, "bad_code", p.Method);
    }

    private static string GenerateOtpCode()
    {
        // 6-digit decimal code using rejection sampling to remove modulo bias.
        Span<byte> buf = stackalloc byte[4];
        Span<char> digits = stackalloc char[6];
        for (var i = 0; i < 6; i++)
        {
            uint value;
            do
            {
                RandomNumberGenerator.Fill(buf);
                value = BitConverter.ToUInt32(buf);
            } while (value >= uint.MaxValue / 10 * 10); // drop the short last slice of the uint range
            digits[i] = (char)('0' + (int)(value % 10));
        }
        return new string(digits);
    }

    private static string ComputeSha256Hex(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
