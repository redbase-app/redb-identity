using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using OpenIddict.Abstractions;

namespace redb.Identity.Core.Services;

/// <summary>
/// Manages explicit user consent grants. Consent is stored as an OpenIddict Authorization
/// with <c>Type = "permanent"</c> and <c>Status = "valid"</c>.
/// This is a thin wrapper over <see cref="IRedbService"/> that queries
/// <see cref="AuthorizationProps"/> directly for performance.
/// </summary>
public sealed class ConsentService
{
    private readonly IRedbService _redb;

    public ConsentService(IRedbService redb) => _redb = redb;

    /// <summary>
    /// Checks whether the user has an existing valid permanent consent for the given application
    /// that covers all the requested scopes.
    /// </summary>
    /// <returns>The matching consent authorization, or <c>null</c> if none found.</returns>
    public async Task<RedbObject<AuthorizationProps>?> CheckAsync(
        long userId, long applicationId, IReadOnlyCollection<string> requestedScopes,
        CancellationToken ct = default)
    {
        var candidates = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.ApplicationObjectId == applicationId)
            .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
            .Where(a => a.Type == OpenIddictConstants.AuthorizationTypes.Permanent)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var candidate in candidates)
        {
            var grantedScopes = candidate.Props.Scopes ?? [];
            if (requestedScopes.All(s => grantedScopes.Contains(s)))
                return candidate;
        }

        return null;
    }

    /// <summary>
    /// Creates or extends a permanent consent grant.
    /// If an existing valid permanent authorization exists for the same user+app,
    /// its scopes are merged (union) with the new scopes.
    /// </summary>
    /// <returns>The created or updated consent authorization.</returns>
    public async Task<RedbObject<AuthorizationProps>> GrantAsync(
        long userId, long applicationId, IReadOnlyCollection<string> scopes,
        CancellationToken ct = default)
    {
        // Check for existing consent to merge scopes
        var existing = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.ApplicationObjectId == applicationId)
            .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
            .Where(a => a.Type == OpenIddictConstants.AuthorizationTypes.Permanent)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (existing is not null)
        {
            var merged = (existing.Props.Scopes ?? []).Union(scopes).Distinct().ToArray();
            existing.Props.Scopes = merged;
            await _redb.SaveAsync(existing).ConfigureAwait(false);
            return existing;
        }

        var auth = new RedbObject<AuthorizationProps>
        {
            key = userId,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = applicationId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.AuthorizationTypes.Permanent,
                Scopes = scopes.ToArray()
            }
        };

        auth.id = await _redb.SaveAsync(auth).ConfigureAwait(false);
        return auth;
    }

    /// <summary>
    /// Revokes all permanent consent grants for a user+application pair.
    /// </summary>
    /// <returns>Number of consents revoked.</returns>
    public async Task<int> RevokeAsync(
        long userId, long applicationId, CancellationToken ct = default)
    {
        var targets = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.ApplicationObjectId == applicationId)
            .Where(a => a.Type == OpenIddictConstants.AuthorizationTypes.Permanent)
            .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var target in targets)
        {
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;
            await _redb.SaveAsync(target).ConfigureAwait(false);
        }

        return targets.Count;
    }

    /// <summary>
    /// Revokes ALL permanent consent grants for a user (across all applications).
    /// </summary>
    public async Task<int> RevokeAllAsync(long userId, CancellationToken ct = default)
    {
        var targets = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.Type == OpenIddictConstants.AuthorizationTypes.Permanent)
            .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var target in targets)
        {
            target.Props.Status = OpenIddictConstants.Statuses.Revoked;
            await _redb.SaveAsync(target).ConfigureAwait(false);
        }

        return targets.Count;
    }

    /// <summary>
    /// Lists all valid permanent consent grants for a user.
    /// Includes application info (ClientId, DisplayName) by loading the referenced apps.
    /// <para>
    /// Application metadata is fetched in a single batched <c>WhereInRedb(o =&gt; o.Id, ids)</c>
    /// query rather than per-row <see cref="IRedbService.LoadAsync"/> — a power user (or a
    /// service-principal that accumulated many <c>permanent</c> grants over time) would
    /// otherwise turn this admin endpoint into an O(N) round-trip storm. Production
    /// repro: a single user with ~1300 permanent grants caused this method to take ~10 s
    /// because each <c>ApplicationProps</c> load was a separate DB round-trip.
    /// </para>
    /// </summary>
    public async Task<List<ConsentInfo>> ListAsync(long userId, CancellationToken ct = default)
    {
        var consents = await _redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(a => a.Type == OpenIddictConstants.AuthorizationTypes.Permanent)
            .Where(a => a.Status == OpenIddictConstants.Statuses.Valid)
            .ToListAsync()
            .ConfigureAwait(false);

        // Batch-fetch every distinct ApplicationProps in ONE query instead of per-row
        // LoadAsync. The Dictionary lookup below replaces the N+1 round-trip pattern.
        var appIds = consents
            .Where(c => c.Props.ApplicationObjectId > 0)
            .Select(c => c.Props.ApplicationObjectId)
            .Distinct()
            .ToArray();

        var appsById = new Dictionary<long, RedbObject<ApplicationProps>>(appIds.Length);
        if (appIds.Length > 0)
        {
            var apps = await _redb.Query<ApplicationProps>()
                .WhereInRedb(o => o.Id, appIds)
                .ToListAsync()
                .ConfigureAwait(false);

            // Hydrate copies _objects.value_string -> Props.ClientId, since ClientId is
            // [RedbIgnore] and stored on the base object, not the PROPS facets.
            foreach (var app in apps)
                appsById[app.id] = app.Hydrate();
        }

        var result = new List<ConsentInfo>(consents.Count);

        foreach (var consent in consents)
        {
            string? clientId = null;
            string? appName = null;

            if (consent.Props.ApplicationObjectId > 0
                && appsById.TryGetValue(consent.Props.ApplicationObjectId, out var app))
            {
                clientId = app.Props.ClientId;
                appName = app.Name;
            }

            result.Add(new ConsentInfo
            {
                Id = consent.id,
                UserId = consent.key ?? 0,
                ApplicationId = consent.Props.ApplicationObjectId,
                ClientId = clientId,
                ApplicationName = appName,
                Scopes = consent.Props.Scopes ?? [],
                CreatedAt = consent.date_create
            });
        }

        return result;
    }

    /// <summary>
    /// Finds the application object ID by client_id.
    /// </summary>
    public async Task<long?> FindApplicationIdAsync(string clientId, CancellationToken ct = default)
    {
        var app = await _redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == clientId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        return app?.id;
    }

    public sealed class ConsentInfo
    {
        public long Id { get; set; }
        public long UserId { get; set; }
        public long ApplicationId { get; set; }
        public string? ClientId { get; set; }
        public string? ApplicationName { get; set; }
        public string[] Scopes { get; set; } = [];
        public DateTimeOffset CreatedAt { get; set; }
    }
}
