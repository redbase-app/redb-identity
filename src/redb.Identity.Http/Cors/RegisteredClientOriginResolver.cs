using Microsoft.AspNetCore.Http;
using redb.Identity.Contracts.Cors;

namespace redb.Identity.Http.Cors;

/// <summary>
/// HTTP-side adapter that exposes <see cref="IRegisteredClientOriginRegistry"/> as a
/// per-request CORS origin resolver compatible with <c>RouteCorsOptions.OriginsResolver</c>.
/// <para>
/// The resolver is intentionally synchronous: <c>RouteCorsOptions.OriginsResolver</c> takes
/// a <see cref="Func{HttpRequest, String}"/>, and the underlying registry exposes an async
/// API. We bridge by blocking on the <see cref="ValueTask{TResult}"/> only when it has not
/// already completed synchronously \u2014 in steady state the snapshot is in-memory, so this
/// path is non-blocking. The first call after <see cref="IRegisteredClientOriginRegistry.Invalidate"/>
/// pays the rebuild cost; subsequent CORS preflights are O(1) hash lookups.
/// </para>
/// </summary>
public sealed class RegisteredClientOriginResolver
{
    private readonly IRegisteredClientOriginRegistry _registry;

    public RegisteredClientOriginResolver(IRegisteredClientOriginRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    /// <summary>
    /// Resolves the request's <c>Origin</c> against the registered-client whitelist.
    /// Returns the original origin string when allowed (so the dispatcher echoes it back
    /// verbatim) or <c>null</c> when not registered (no CORS headers will be emitted).
    /// </summary>
    public string? Resolve(HttpRequest request)
    {
        var origin = request.Headers["Origin"].ToString();
        if (string.IsNullOrEmpty(origin)) return null;

        var task = _registry.IsAllowedAsync(origin, request.HttpContext.RequestAborted);
        var allowed = task.IsCompletedSuccessfully
            ? task.Result
            // First-call rebuild path: blocking GetAwaiter().GetResult() is acceptable here because
            // the work is bounded (one OpenIddict ListAsync) and serialised by the registry's
            // semaphore, so concurrent preflights do not stampede the store.
            : task.AsTask().GetAwaiter().GetResult();

        return allowed ? origin : null;
    }
}
