using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Identity.Contracts.Cors;

namespace redb.Identity.Core.Security;

/// <summary>
/// Default <see cref="IRegisteredClientOriginRegistry"/> implementation backed by
/// <see cref="IOpenIddictApplicationManager"/>. Rebuilds its snapshot lazily on demand
/// after <see cref="IRegisteredClientOriginRegistry.Invalidate"/>; concurrent rebuilds are
/// de-duplicated via a <see cref="SemaphoreSlim"/> so a burst of CORS preflights does not
/// trigger N parallel store scans.
/// </summary>
public sealed class RegisteredClientOriginRegistry : IRegisteredClientOriginRegistry
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly Func<string>? _additionalOriginsCsv;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private volatile ImmutableHashSet<string>? _snapshot;
    private int _generation; // bumped by Invalidate; observed by readers to skip stale snapshots

    /// <summary>Creates a new registry.</summary>
    /// <param name="scopeFactory">DI scope factory used to resolve a fresh
    /// <see cref="IOpenIddictApplicationManager"/> (a Scoped service) on every snapshot rebuild.
    /// Critical: holding a captured <see cref="IOpenIddictApplicationManager"/> as a field
    /// here is a captive-singleton bug because the manager transitively closes over the
    /// Scoped <c>IRedbService</c> and therefore over a single <c>NpgsqlConnection</c> — every
    /// CORS preflight would then share that one connection with any in-flight request, which
    /// surfaces as <c>NpgsqlOperationInProgressException: A command is already in progress</c>.
    /// </param>
    /// <param name="additionalOriginsCsv">Optional callback returning a comma-separated list of
    /// origins always considered allowed (e.g. dev/staging fallbacks supplied via configuration).
    /// Evaluated on every refresh so config hot-reload is picked up. May return null.</param>
    public RegisteredClientOriginRegistry(
        IServiceScopeFactory scopeFactory,
        Func<string?>? additionalOriginsCsv = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _additionalOriginsCsv = additionalOriginsCsv is null ? null : () => additionalOriginsCsv() ?? string.Empty;
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsAllowedAsync(string? origin, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(origin)) return false;
        var snapshot = await GetAllowedOriginsAsync(ct).ConfigureAwait(false);
        return snapshot.Contains(origin);
    }

    /// <inheritdoc />
    public async ValueTask<ImmutableHashSet<string>> GetAllowedOriginsAsync(CancellationToken ct = default)
    {
        var current = _snapshot;
        if (current is not null) return current;

        await _refreshLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Re-check after acquiring the lock: another thread may have rebuilt while we waited.
            current = _snapshot;
            if (current is not null) return current;

            var rebuilt = await BuildAsync(ct).ConfigureAwait(false);
            _snapshot = rebuilt;
            return rebuilt;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <inheritdoc />
    public void Invalidate()
    {
        _snapshot = null;
        Interlocked.Increment(ref _generation);
    }

    private async Task<ImmutableHashSet<string>> BuildAsync(CancellationToken ct)
    {
        var builder = ImmutableHashSet.CreateBuilder<string>(StringComparer.OrdinalIgnoreCase);

        // Resolve the application manager from a fresh DI scope so its transitive
        // dependencies (notably the Scoped IRedbService -> NpgsqlConnection chain) live and
        // die with this single rebuild. See ctor doc for why a captured manager would be a
        // captive-singleton bug.
        await using var scope = _scopeFactory.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        await foreach (var app in applications.ListAsync(count: null, offset: null, ct).ConfigureAwait(false))
        {
            if (app is null) continue;

            var redirectUris = await applications.GetRedirectUrisAsync(app, ct).ConfigureAwait(false);
            foreach (var uri in redirectUris)
                AddOrigin(builder, uri);

            var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(app, ct).ConfigureAwait(false);
            foreach (var uri in postLogoutUris)
                AddOrigin(builder, uri);
        }

        // Additional configured origins (dev/staging fallbacks). Evaluated on every refresh so
        // operators can toggle them without restarting the process.
        var additional = _additionalOriginsCsv?.Invoke();
        if (!string.IsNullOrEmpty(additional))
        {
            foreach (var raw in additional.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                AddOrigin(builder, raw);
        }

        return builder.ToImmutable();
    }

    private static void AddOrigin(ImmutableHashSet<string>.Builder builder, string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return;

        // Accept either a bare origin ("https://app.example.com") or a full redirect URI
        // ("https://app.example.com/callback?x=1") -- in both cases we want the authority only.
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed))
            return;
        if (string.IsNullOrEmpty(parsed.Scheme) || string.IsNullOrEmpty(parsed.Host))
            return;

        // Use Uri.GetLeftPart(Authority) which already strips userinfo, path, and query, and
        // collapses the default port for http/https. Lower-case to match browser-emitted Origin.
        var origin = parsed.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        builder.Add(origin);
    }
}
