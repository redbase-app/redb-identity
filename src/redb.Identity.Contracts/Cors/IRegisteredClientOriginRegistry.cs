using System.Collections.Immutable;

namespace redb.Identity.Contracts.Cors;

/// <summary>
/// In-memory registry of allowed CORS origins derived from registered OAuth clients'
/// <c>RedirectUris</c> and <c>PostLogoutRedirectUris</c>. This is the runtime data source
/// used by the HTTP transport's per-route CORS resolver to authorise browser-initiated
/// requests to OIDC endpoints (token, userinfo, revocation, ...).
/// <para>
/// The registry is invalidation-driven, not TTL-driven: management operations
/// (<c>Create</c>/<c>Update</c>/<c>Delete</c> on applications) call <see cref="Invalidate"/>
/// to mark the snapshot stale, and the next read repopulates from the underlying store.
/// There is no background refresh.
/// </para>
/// <para>
/// Origins are normalised to <c>{scheme}://{host}[:{port}]</c>. URIs whose authority cannot
/// be parsed are silently skipped — they are management-API validation failures, not CORS
/// failures.
/// </para>
/// <para>
/// Lives in <c>redb.Identity.Contracts</c> so that transport facades (HTTP, gRPC, ...) can
/// consume it without taking a compile-time reference to the Core implementation assembly.
/// </para>
/// </summary>
public interface IRegisteredClientOriginRegistry
{
    /// <summary>
    /// Returns true if <paramref name="origin"/> matches at least one registered client's
    /// redirect or post-logout URI authority. Comparison is case-insensitive on host/scheme;
    /// port and path components must match the URI exactly as registered.
    /// </summary>
    /// <param name="origin">The browser-supplied <c>Origin</c> request header value.</param>
    ValueTask<bool> IsAllowedAsync(string? origin, CancellationToken ct = default);

    /// <summary>
    /// Returns the current snapshot of allowed origins. Useful for diagnostics and tests.
    /// Triggers a refresh if the registry has been invalidated.
    /// </summary>
    ValueTask<ImmutableHashSet<string>> GetAllowedOriginsAsync(CancellationToken ct = default);

    /// <summary>
    /// Marks the cached snapshot stale. The next call to <see cref="IsAllowedAsync"/> will
    /// rebuild from the underlying source. Cheap and idempotent; safe to call from
    /// management-API processors after every mutation.
    /// </summary>
    void Invalidate();
}
