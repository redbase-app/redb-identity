using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Security;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Security;

/// <summary>
/// H10 Phase 2 — PROPS-backed <see cref="IPasswordHistoryStore"/> that mirrors the
/// <c>PropsWebAuthnChallengeStore</c> pattern: registered as a singleton, opens a fresh
/// DI scope per call so the captured <see cref="IRedbService"/> is never captive across
/// requests. Verifier-hashes are produced via the registered
/// <see cref="IPasswordHasher"/> (Argon2id by default; same hasher used for live
/// credentials so a future algorithm bump is automatically picked up).
/// </summary>
public sealed class PropsPasswordHistoryStore : IPasswordHistoryStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PropsPasswordHistoryStore>? _logger;

    public PropsPasswordHistoryStore(
        IServiceScopeFactory scopeFactory,
        TimeProvider? timeProvider = null,
        ILogger<PropsPasswordHistoryStore>? logger = null)
    {
        _scopeFactory = scopeFactory ?? throw new System.ArgumentNullException(nameof(scopeFactory));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<bool> IsRecentlyUsedAsync(long userId, string password, int count, CancellationToken ct)
    {
        if (userId <= 0 || count <= 0 || string.IsNullOrEmpty(password))
            return false;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        // Pull the most recent N history rows for the user; ordering by CreatedAt desc.
        // Argon2id verify is O(~100ms each), so we cap the work by `count` upstream.
        var rows = await redb.Query<PasswordHistoryProps>()
            .Where(o => o.UserId == userId)
            .OrderByDescending(o => o.CreatedAt)
            .Take(count)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var row in rows)
        {
            var stored = row.Props.HashedPassword;
            if (!string.IsNullOrEmpty(stored)
                && hasher.VerifyPassword(password, stored))
            {
                return true;
            }
        }
        return false;
    }

    /// <inheritdoc />
    public async Task RecordAsync(long userId, string password, int keep, CancellationToken ct)
    {
        if (userId <= 0 || string.IsNullOrEmpty(password) || keep <= 0)
            return;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        var now = _timeProvider.GetUtcNow();
        var entry = new RedbObject<PasswordHistoryProps>(new PasswordHistoryProps
        {
            UserId = userId,
            HashedPassword = hasher.HashPassword(password),
            CreatedAt = now,
        })
        {
            name = $"pwhist:{userId}:{now.ToUnixTimeMilliseconds()}",
        };

        await redb.SaveAsync(entry).ConfigureAwait(false);

        // Trim: soft-delete everything older than the keep-newest-N window. Cleaning up
        // here keeps the table O(N*users) without a separate cleanup processor.
        try
        {
            var staleIds = await redb.Query<PasswordHistoryProps>()
                .Where(o => o.UserId == userId)
                .OrderByDescending(o => o.CreatedAt)
                .Skip(keep)
                .Select(o => o.id)
                .ToListAsync()
                .ConfigureAwait(false);

            if (staleIds.Count > 0)
            {
                await redb.SoftDeleteAsync(staleIds).ConfigureAwait(false);
            }
        }
        catch (System.Exception ex)
        {
            // Trim failures must not block password change — at worst the table grows
            // a bit until the next successful trim.
            _logger?.LogWarning(ex,
                "Password-history trim failed for userId={UserId}; keep window not enforced this round.",
                userId);
        }
    }
}
