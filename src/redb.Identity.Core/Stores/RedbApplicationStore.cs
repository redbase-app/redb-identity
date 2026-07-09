using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;

namespace redb.Identity.Core.Stores;

/// <summary>
/// OpenIddict application store backed by redb PROPS storage.
/// Entity type: <see cref="RedbObject{ApplicationProps}"/>.
/// </summary>
internal sealed class RedbApplicationStore : IOpenIddictApplicationStore<RedbObject<ApplicationProps>>
{
    private readonly IRedbService _redb;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly ILogger? _logger;

    // [STORE-DIAG] per-request call counters & cumulative ms.
    // Store is Scoped, so these track one HTTP request only.
    private int _fbcidCalls, _fbcidHits, _fbidCalls;
    private long _fbcidMs, _fbidMs;

    // Per-request cache: store is Scoped (one instance per HTTP request), so this
    // dict lives only for the lifetime of one OIDC pipeline invocation. OpenIddict
    // built-in handlers call FindByClientIdAsync 8-11× per /connect/token request
    // for the same client_id; without a cache each call hits PVT join (~8ms each).
    // Caches null too — defends against repeated lookups for unknown client_ids.
    private readonly Dictionary<string, RedbObject<ApplicationProps>?> _clientIdCache = new(StringComparer.Ordinal);

    public RedbApplicationStore(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion = null,
        ILogger<RedbApplicationStore>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(redb);
        _redb = redb;
        _backgroundDeletion = backgroundDeletion;
        _logger = logger;
    }

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        return await _redb.Query<ApplicationProps>()
            .CountAsync()
            .ConfigureAwait(false);
    }

    public async ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RedbObject<ApplicationProps>>, IQueryable<TResult>> query,
        CancellationToken cancellationToken)
    {
        // OpenIddict managers do NOT call this internally — external code only.
        // Delegate to server-side CountAsync when the projected query is trivial.
        return await CountAsync(cancellationToken);
    }

    public async ValueTask CreateAsync(RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.value_string = application.Props.ClientId;
        application.id = await _redb.SaveAsync(application).ConfigureAwait(false);
        if (application.value_string is { } cid)
            _clientIdCache[cid] = application;
    }

    public async ValueTask DeleteAsync(RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        // Identity-wide deletion pattern: enqueue via background service if available,
        // otherwise fall back to SoftDelete. Application drags Authorization/Token cascades —
        // hard-delete here would block the request thread.
        await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, application.id).ConfigureAwait(false);
        if (application.value_string is { } cid)
            _clientIdCache.Remove(cid);
    }

    public async ValueTask<RedbObject<ApplicationProps>?> FindByIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (!long.TryParse(identifier, out var id))
            return null;

        var sw = Stopwatch.GetTimestamp();
        // Use Query<>(): it filters out soft-deleted objects (trash scheme).
        // LoadAsync<>() loads by primary key and ignores deletion state.
        var app = await _redb.Query<ApplicationProps>()
            .WhereRedb(o => o.Id == id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (app != null) app.Hydrate();
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbidCalls;
        _fbidMs += ms;
        _logger?.LogDebug("[STORE-DIAG] App.FindById call#{N} ms={Ms} cum={Cum} id={Id}",
            n, ms, _fbidMs, identifier);
        return app;
    }

    public async ValueTask<RedbObject<ApplicationProps>?> FindByClientIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        if (_clientIdCache.TryGetValue(identifier, out var cached))
        {
            var nh = ++_fbcidCalls;
            _fbcidHits++;
            _logger?.LogDebug("[STORE-DIAG] App.FindByClientId call#{N} HIT hits={Hits} cum={Cum} cid={Cid}",
                nh, _fbcidHits, _fbcidMs, identifier);
            return cached;
        }

        var sw = Stopwatch.GetTimestamp();
        var app = await _redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == identifier)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (app != null) app.Hydrate();
        _clientIdCache[identifier] = app;
        var ms = (long)Stopwatch.GetElapsedTime(sw).TotalMilliseconds;
        var n = ++_fbcidCalls;
        _fbcidMs += ms;
        _logger?.LogDebug("[STORE-DIAG] App.FindByClientId call#{N} MISS ms={Ms} cum={Cum} cid={Cid}",
            n, ms, _fbcidMs, identifier);
        return app;
    }

    public async IAsyncEnumerable<RedbObject<ApplicationProps>> FindByPostLogoutRedirectUriAsync(
        string uri, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Array.Contains — verified working in redb PROPS (see E050_ArrayContains)
        var results = await _redb.Query<ApplicationProps>()
            .Where(a => a.PostLogoutRedirectUris != null && a.PostLogoutRedirectUris.Contains(uri))
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
            yield return result.Hydrate();
    }

    public async IAsyncEnumerable<RedbObject<ApplicationProps>> FindByRedirectUriAsync(
        string uri, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var results = await _redb.Query<ApplicationProps>()
            .Where(a => a.RedirectUris != null && a.RedirectUris.Contains(uri))
            .ToListAsync()
            .ConfigureAwait(false);

        foreach (var result in results)
            yield return result.Hydrate();
    }

    public ValueTask<string?> GetApplicationTypeAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.ApplicationType);
    }

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RedbObject<ApplicationProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<ApplicationProps>() directly.");
    }

    public ValueTask<string?> GetClientIdAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.value_string ?? application.Props.ClientId);
    }

    public ValueTask<string?> GetClientSecretAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.ClientSecret);
    }

    public ValueTask<string?> GetClientTypeAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.ClientType);
    }

    public ValueTask<string?> GetConsentTypeAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.ConsentType);
    }

    public ValueTask<string?> GetDisplayNameAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.name);
    }

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var names = application.Props.DisplayNames;
        if (names is null || names.Count == 0)
            return new(ImmutableDictionary<CultureInfo, string>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();
        foreach (var (key, value) in names)
            builder[CultureInfo.GetCultureInfo(key)] = value;

        return new(builder.ToImmutable());
    }

    public ValueTask<string?> GetIdAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.id.ToString());
    }

    public ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        if (string.IsNullOrEmpty(application.Props.JsonWebKeySet))
            return new(result: null);

        return new(JsonWebKeySet.Create(application.Props.JsonWebKeySet));
    }

    public ValueTask<ImmutableArray<string>> GetPermissionsAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.Permissions?.ToImmutableArray() ?? []);
    }

    public ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.PostLogoutRedirectUris?.ToImmutableArray() ?? []);
    }

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var props = application.Props.Properties;
        if (props is null || props.Count == 0)
            return new(ImmutableDictionary<string, JsonElement>.Empty);

        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        foreach (var (key, value) in props)
            builder[key] = JsonSerializer.Deserialize<JsonElement>(value);

        return new(builder.ToImmutable());
    }

    public ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.RedirectUris?.ToImmutableArray() ?? []);
    }

    public ValueTask<ImmutableArray<string>> GetRequirementsAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        return new(application.Props.Requirements?.ToImmutableArray() ?? []);
    }

    public ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(
        RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var settings = application.Props.Settings;
        if (settings is null || settings.Count == 0)
            return new(ImmutableDictionary<string, string>.Empty);

        return new(settings.ToImmutableDictionary());
    }

    public ValueTask<RedbObject<ApplicationProps>> InstantiateAsync(CancellationToken cancellationToken)
    {
        return new(new RedbObject<ApplicationProps> { Props = new ApplicationProps() });
    }

    public async IAsyncEnumerable<RedbObject<ApplicationProps>> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        IRedbQueryable<ApplicationProps> query = _redb.Query<ApplicationProps>().OrderByRedb<long>(o => o.Id);

        if (offset.HasValue)
            query = query.Skip(offset.Value);
        if (count.HasValue)
            query = query.Take(count.Value);

        var results = await query.ToListAsync().ConfigureAwait(false);

        foreach (var result in results)
            yield return result.Hydrate();
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RedbObject<ApplicationProps>>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        throw new NotSupportedException(
            "Func<IQueryable> cannot be translated to server-side queries. Use _redb.Query<ApplicationProps>() directly.");
    }

    public ValueTask SetApplicationTypeAsync(
        RedbObject<ApplicationProps> application, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.ApplicationType = type;
        return default;
    }

    public ValueTask SetClientIdAsync(
        RedbObject<ApplicationProps> application, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.ClientId = identifier;
        application.value_string = identifier;
        return default;
    }

    public ValueTask SetClientSecretAsync(
        RedbObject<ApplicationProps> application, string? secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.ClientSecret = secret;
        return default;
    }

    public ValueTask SetClientTypeAsync(
        RedbObject<ApplicationProps> application, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.ClientType = type;
        return default;
    }

    public ValueTask SetConsentTypeAsync(
        RedbObject<ApplicationProps> application, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.ConsentType = type;
        return default;
    }

    public ValueTask SetDisplayNameAsync(
        RedbObject<ApplicationProps> application, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.name = name;
        return default;
    }

    public ValueTask SetDisplayNamesAsync(
        RedbObject<ApplicationProps> application,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Props.DisplayNames = names.ToDictionary(
            kvp => kvp.Key.Name, kvp => kvp.Value);
        return default;
    }

    public ValueTask SetJsonWebKeySetAsync(
        RedbObject<ApplicationProps> application, JsonWebKeySet? set, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.JsonWebKeySet = set is not null
            ? JsonSerializer.Serialize(set)
            : null;
        return default;
    }

    public ValueTask SetPermissionsAsync(
        RedbObject<ApplicationProps> application, ImmutableArray<string> permissions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.Permissions = permissions.IsDefaultOrEmpty ? null : [.. permissions];
        return default;
    }

    public ValueTask SetPostLogoutRedirectUrisAsync(
        RedbObject<ApplicationProps> application, ImmutableArray<string> uris,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.PostLogoutRedirectUris = uris.IsDefaultOrEmpty ? null : [.. uris];
        return default;
    }

    public ValueTask SetPropertiesAsync(
        RedbObject<ApplicationProps> application,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        if (properties is null || properties.IsEmpty)
        {
            application.Props.Properties = null;
            return default;
        }

        application.Props.Properties = properties.ToDictionary(
            kvp => kvp.Key, kvp => kvp.Value.GetRawText());
        return default;
    }

    public ValueTask SetRedirectUrisAsync(
        RedbObject<ApplicationProps> application, ImmutableArray<string> uris,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.RedirectUris = uris.IsDefaultOrEmpty ? null : [.. uris];
        return default;
    }

    public ValueTask SetRequirementsAsync(
        RedbObject<ApplicationProps> application, ImmutableArray<string> requirements,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.Requirements = requirements.IsDefaultOrEmpty ? null : [.. requirements];
        return default;
    }

    public ValueTask SetSettingsAsync(
        RedbObject<ApplicationProps> application,
        ImmutableDictionary<string, string> settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        application.Props.Settings = settings is null || settings.IsEmpty
            ? null
            : settings.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        return default;
    }

    public async ValueTask UpdateAsync(RedbObject<ApplicationProps> application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        // C11: cluster-safe atomic update — see RedbTokenStore.UpdateAsync.
        await _redb.Context.ExecuteAtomicAsync(async () =>
        {
            await _redb.LockForUpdateAsync(application.id).ConfigureAwait(false);

            var current = await _redb.LoadAsync<ApplicationProps>(application.id).ConfigureAwait(false);
            if (current is null)
                throw new OpenIddictExceptions.ConcurrencyException("The application was concurrently deleted.");

            if (current.hash != application.hash)
                throw new OpenIddictExceptions.ConcurrencyException("The application was concurrently updated.");

            application.value_string = application.Props.ClientId;
            await _redb.SaveAsync(application).ConfigureAwait(false);
        }).ConfigureAwait(false);

        if (application.value_string is { } cid)
            _clientIdCache[cid] = application;
    }
}
