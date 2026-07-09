using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Core.Services;

/// <summary>
/// H5 (v1.0 DoD §5): Resolves declarative <see cref="ClaimMapperProps"/> rules and applies
/// them to a <see cref="ClaimsPrincipal"/> at token-issuance time.
/// <para>
/// Resolution scope (in apply order, last write wins per <c>ClaimType</c>):
/// <list type="number">
///   <item><b>Global</b> rules: <c>parent_id IS NULL</c>.</item>
///   <item><b>Assigned Client Scope</b> rules: <c>parent_id IN (assigned scope ids)</c>.</item>
///   <item><b>Per-application overlay</b> rules: <c>parent_id = applicationId</c>.</item>
/// </list>
/// Within the same precedence band, <see cref="ClaimMapperProps.Order"/> ascending breaks
/// ties (last in <c>Order</c> wins).
/// </para>
/// <para>
/// Mirror of Keycloak's "default scope mappers + assigned client scopes + client mappers"
/// composition, applied at the OpenIddict <c>ProcessSignInContext</c> stage.
/// </para>
/// </summary>
public sealed class ClaimMappersResolver
{
    private readonly IRedbService _redb;
    private readonly ILogger<ClaimMappersResolver>? _logger;

    /// <summary>Reflected getter cache for <see cref="UserProps"/> dotted paths.</summary>
    private static readonly ConcurrentDictionary<string, Func<UserProps, object?>?> _propPathCache = new();

    public ClaimMappersResolver(IRedbService redb, ILogger<ClaimMappersResolver>? logger = null)
    {
        _redb = redb ?? throw new ArgumentNullException(nameof(redb));
        _logger = logger;
    }

    /// <summary>
    /// Loads applicable mappers, resolves their values and adds claims to
    /// <paramref name="principal"/>'s identity. Existing claims with the same
    /// <see cref="ClaimMapperProps.ClaimType"/> are removed before the mapper-emitted
    /// claim is added (mappers ALWAYS override values from
    /// <see cref="UserProps.CustomClaims"/> and other earlier sources for their claim type).
    /// </summary>
    /// <param name="principal">Principal to enrich. <c>null</c> identity = no-op.</param>
    /// <param name="userId">Subject id for resolving <c>UserProps</c> sources.</param>
    /// <param name="applicationId">
    /// Object id of the OAuth application receiving the token, or <c>null</c> for grants
    /// without a client (e.g. some service-to-service flows). When <c>null</c>, only global
    /// mappers run; per-app overlay and assigned scopes are skipped.
    /// </param>
    /// <param name="requestedScopes">Scopes requested for this issuance.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a mapper marked <see cref="ClaimMapperProps.Required"/> resolves to a
    /// null / empty value. Caller (OpenIddict handler) should translate to
    /// <c>error=invalid_request</c>.
    /// </exception>
    public async Task EnrichPrincipalAsync(
        ClaimsPrincipal principal,
        long userId,
        long? applicationId,
        IEnumerable<string> requestedScopes,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Identity is not ClaimsIdentity identity)
            return;

        var scopeSet = new HashSet<string>(
            requestedScopes ?? Array.Empty<string>(),
            StringComparer.Ordinal);

        // ── 1. Load all applicable mapper rules in two queries ──
        // Sequential by design: IRedbService is not thread-safe across concurrent
        // operations on the same instance (same constraint as EF DbContext).
        // Reduce round-trips by collapsing global + per-app-overlay into ONE
        // query (parent_id IS NULL OR parent_id == appId), and pushing the
        // `Enabled` and scope-id filters down to the database — the resolver
        // never needs disabled rules in memory.
        // NOTE: defensive `?? []` on every ToListAsync() result. IRedbService is a
        // public interface; substitute/mock implementations may return Task<List<T>>
        // with a null Result. Production (EF) never does, but this resolver runs from
        // an OpenIddict server handler that we cannot easily disable per-test, so
        // tolerating null-list returns prevents NREs in unit tests that never set up
        // ClaimMapper queries. Empty list = "no mappers" = correct behavior.
        List<RedbObject<ClaimMapperProps>> globalMappers;
        List<RedbObject<ClaimMapperProps>> appOverlayMappers = [];
        List<RedbObject<ClaimMapperProps>> scopeMappers = [];

        if (applicationId is long appId && appId > 0)
        {
            // One query covers both global (parent_id IS NULL) and per-app overlay
            // (parent_id == appId). Split locally by parent_id.
            var globalAndOverlay = (await _redb.Query<ClaimMapperProps>()
                .WhereRedb(o => o.ParentId == null || o.ParentId == appId)
                .Where(m => m.Enabled)
                .ToListAsync().ConfigureAwait(false)) ?? [];

            globalMappers = globalAndOverlay.Where(m => m.ParentId is null).ToList();
            appOverlayMappers = globalAndOverlay.Where(m => m.ParentId == appId).ToList();

            // Resolve assigned Client Scopes for the application
            var assignments = (await _redb.Query<ClaimScopeAssignmentProps>()
                .WhereRedb(o => o.Key == appId)
                .ToListAsync().ConfigureAwait(false)) ?? [];

            var assignedScopeIds = assignments
                .Select(a => a.Props.ScopeId)
                .Where(id => id > 0)
                .Distinct()
                .ToList();

            if (assignedScopeIds.Count > 0)
            {
                // Server-side filter + projection: only enabled scopes, return ids only.
                // Avoids materialising full ClaimScopeProps rows just to read the id.
                var enabledScopeIds = (await _redb.Query<ClaimScopeProps>()
                    .WhereInRedb(o => o.Id, assignedScopeIds)
                    .Where(s => s.Enabled)
                    .Select(o => o.id)
                    .ToListAsync().ConfigureAwait(false)) ?? [];

                if (enabledScopeIds.Count > 0)
                {
                    var enabledScopeIdsAsParent = enabledScopeIds.Cast<long?>().ToList();
                    scopeMappers = (await _redb.Query<ClaimMapperProps>()
                        .WhereInRedb(o => o.ParentId, enabledScopeIdsAsParent)
                        .Where(m => m.Enabled)
                        .ToListAsync().ConfigureAwait(false)) ?? [];
                }
            }
        }
        else
        {
            // No application context — only global mappers apply.
            globalMappers = (await _redb.Query<ClaimMapperProps>()
                .WhereRedb(o => o.ParentId == null)
                .Where(m => m.Enabled)
                .ToListAsync().ConfigureAwait(false)) ?? [];
        }

        var allMappers = globalMappers
            .Concat(scopeMappers)
            .Concat(appOverlayMappers)
            .ToList();

        // Filter: scope-gated (Enabled already enforced at the DB layer above).
        var applicable = allMappers
            .Where(m => MatchesRequiredScopes(m.Props.RequiredScopes, scopeSet))
            .OrderBy(m => GetPrecedence(m, applicationId))   // global=0, scope=1, app=2
            .ThenBy(m => m.Props.Order)
            .ToList();

        if (applicable.Count == 0)
            return;

        // ── 2. Lazy-load UserProps ONCE if any mapper needs it ──
        UserProps? userProps = null;
        if (applicable.Any(m => NeedsUserProps(m.Props.SourceKind)))
        {
            var oidcObj = await _redb.Query<UserProps>()
                .WhereRedb(o => o.Key == userId)
                .FirstOrDefaultAsync().ConfigureAwait(false);
            userProps = oidcObj?.Props;
        }

        // ── 3. Resolve + apply with last-write-wins by ClaimType ──
        var emitted = new Dictionary<string, (string Value, string[] Destinations)>(StringComparer.Ordinal);

        foreach (var mapper in applicable)
        {
            var props = mapper.Props;
            var claimType = props.ClaimType?.Trim();
            if (string.IsNullOrEmpty(claimType))
            {
                _logger?.LogWarning("ClaimMapper {Id} has empty ClaimType; skipped", mapper.Id);
                continue;
            }

            string? value;
            try
            {
                value = ResolveValue(props, userProps);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "ClaimMapper {Id} ({ClaimType}) value resolution failed", mapper.Id, claimType);
                if (props.Required)
                    throw new InvalidOperationException(
                        $"Required claim mapper '{claimType}' (id {mapper.Id}) failed to resolve: {ex.Message}", ex);
                continue;
            }

            if (string.IsNullOrEmpty(value))
            {
                if (props.Required)
                    throw new InvalidOperationException(
                        $"Required claim mapper '{claimType}' (id {mapper.Id}) resolved to empty value");
                continue;
            }

            var destinations = NormalizeDestinations(props.Destinations);
            emitted[claimType] = (value, destinations);
        }

        // Apply: remove pre-existing claims for these types, then add
        foreach (var (claimType, payload) in emitted)
        {
            foreach (var existing in identity.FindAll(claimType).ToList())
                identity.RemoveClaim(existing);

            var claim = new Claim(claimType, payload.Value);
            claim.SetDestinations(payload.Destinations);
            identity.AddClaim(claim);
        }
    }

    // ── value resolution helpers ──

    private static bool NeedsUserProps(string? sourceKind)
        => sourceKind is "UserProps" or "CustomClaim";

    private static string? ResolveValue(ClaimMapperProps props, UserProps? userProps)
    {
        return props.SourceKind switch
        {
            "Constant" => props.ConstantValue,
            "CustomClaim" => ResolveCustomClaim(props.SourcePath, userProps),
            "UserProps" => ResolveUserPropsPath(props.SourcePath, userProps),
            _ => throw new InvalidOperationException(
                $"Unknown SourceKind '{props.SourceKind}' (expected: Constant | CustomClaim | UserProps)")
        };
    }

    private static string? ResolveCustomClaim(string? key, UserProps? userProps)
    {
        if (string.IsNullOrEmpty(key) || userProps?.CustomClaims is null)
            return null;
        return userProps.CustomClaims.TryGetValue(key, out var v) ? v : null;
    }

    private static string? ResolveUserPropsPath(string? path, UserProps? userProps)
    {
        if (userProps is null || string.IsNullOrEmpty(path))
            return null;

        var getter = _propPathCache.GetOrAdd(path, BuildPropPathGetter);
        if (getter is null) return null;

        var raw = getter(userProps);
        return raw switch
        {
            null => null,
            string s => s,
            bool b => b ? "true" : "false",
            DateTime dt => dt.ToString("O"),
            DateTimeOffset dto => dto.ToString("O"),
            IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
            _ => JsonSerializer.Serialize(raw)
        };
    }

    private static Func<UserProps, object?>? BuildPropPathGetter(string path)
    {
        // Compiled path traversal: segment.segment.segment via reflection.
        // First segment must be a public instance property of UserProps; subsequent segments
        // resolve against the running value's runtime type. Returns null for any missing segment.
        var segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 0) return null;

        return (UserProps p) =>
        {
            object? current = p;
            foreach (var segment in segments)
            {
                if (current is null) return null;
                var prop = current.GetType().GetProperty(segment,
                    BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                if (prop is null) return null;
                current = prop.GetValue(current);
            }
            return current;
        };
    }

    private static bool MatchesRequiredScopes(string[]? required, HashSet<string> requestedScopes)
    {
        if (required is null || required.Length == 0)
            return true;
        foreach (var scope in required)
        {
            if (!requestedScopes.Contains(scope))
                return false;
        }
        return true;
    }

    private static string[] NormalizeDestinations(string[]? destinations)
    {
        if (destinations is null || destinations.Length == 0)
            return new[] { Destinations.AccessToken, Destinations.IdentityToken };

        var result = new List<string>(destinations.Length);
        foreach (var d in destinations)
        {
            switch (d?.Trim().ToLowerInvariant())
            {
                case "access_token":
                    result.Add(Destinations.AccessToken);
                    break;
                case "id_token":
                case "identity_token":
                    result.Add(Destinations.IdentityToken);
                    break;
                // Unknown destinations silently dropped — admin error in DB shouldn't break issuance.
            }
        }
        return result.Count == 0
            ? new[] { Destinations.AccessToken, Destinations.IdentityToken }
            : result.ToArray();
    }

    private static int GetPrecedence(RedbObject<ClaimMapperProps> mapper, long? applicationId)
    {
        if (mapper.ParentId is null) return 0;
        if (applicationId is long appId && mapper.ParentId == appId) return 2;
        return 1; // scope
    }
}
