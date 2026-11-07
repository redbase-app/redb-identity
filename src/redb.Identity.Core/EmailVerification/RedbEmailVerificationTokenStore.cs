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

namespace redb.Identity.Core.EmailVerification;

/// <summary>
/// N-4 (Session C, sub-step N4-6): redb-backed
/// <see cref="IEmailVerificationTokenStore"/>. Direct mirror of
/// <c>RedbPasswordResetTokenStore</c> with one extra field on the persisted props
/// (<see cref="EmailVerificationTokenProps.Email"/>) and one extra field on the verify
/// result so the caller can guard against the double-change race.
/// </summary>
public sealed class RedbEmailVerificationTokenStore : IEmailVerificationTokenStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly RecoveryCodePepperProvider _pepperProvider;
    private readonly ILogger<RedbEmailVerificationTokenStore> _logger;
    private readonly TimeProvider _timeProvider;

    public RedbEmailVerificationTokenStore(
        IServiceScopeFactory scopeFactory,
        RecoveryCodePepperProvider pepperProvider,
        ILogger<RedbEmailVerificationTokenStore> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _pepperProvider = pepperProvider ?? throw new ArgumentNullException(nameof(pepperProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<EmailVerificationIssueResult> IssueAsync(
        long userId,
        string email,
        string callerVerifyUrl,
        TimeSpan ttl,
        CancellationToken ct = default)
    {
        if (userId <= 0) throw new ArgumentOutOfRangeException(nameof(userId));
        if (string.IsNullOrWhiteSpace(email)) throw new ArgumentException("email is required", nameof(email));
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));

        var jti = Guid.NewGuid();
        var token = GenerateToken();
        var now = _timeProvider.GetUtcNow();
        var expires = now + ttl;
        var hash = ComputePepperedSha256Hex(token);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var obj = new RedbObject<EmailVerificationTokenProps>(new EmailVerificationTokenProps
        {
            Jti = jti.ToString("N"),
            UserId = userId,
            Email = email.Trim().ToLowerInvariant(),
            TokenHash = hash,
            IssuedAt = now,
            ExpiresAt = expires,
            Consumed = false,
            Attempts = 0,
            CallerVerifyUrl = callerVerifyUrl ?? string.Empty,
        });
        obj.name = jti.ToString("N");

        await redb.SaveAsync(obj).ConfigureAwait(false);
        return new EmailVerificationIssueResult(jti, token, expires);
    }

    /// <inheritdoc />
    public async Task<EmailVerificationVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        string token,
        CancellationToken ct = default)
    {
        if (jti == Guid.Empty) return new EmailVerificationVerifyResult(false, 0, string.Empty, "not_found");
        if (string.IsNullOrEmpty(token)) return new EmailVerificationVerifyResult(false, 0, string.Empty, "bad_token");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var key = jti.ToString("N");
        await using var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false);

        var row = await redb.Query<EmailVerificationTokenProps>()
            .Where(o => o.Jti == key)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (row is null)
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            return new EmailVerificationVerifyResult(false, 0, string.Empty, "not_found");
        }

        if (row.key.HasValue)
            await redb.LockForUpdateAsync(row.key.Value).ConfigureAwait(false);

        var p = row.Props;
        var now = _timeProvider.GetUtcNow();

        if (p.Consumed)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new EmailVerificationVerifyResult(false, 0, string.Empty, "already_consumed");
        }
        if (p.ExpiresAt < now)
        {
            await tx.CommitAsync().ConfigureAwait(false);
            return new EmailVerificationVerifyResult(false, 0, string.Empty, "expired");
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
            ? new EmailVerificationVerifyResult(true, p.UserId, p.Email, "ok")
            : new EmailVerificationVerifyResult(false, 0, string.Empty, "bad_token");
    }

    private static string GenerateToken()
    {
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
