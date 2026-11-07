using redb.Route.Abstractions;

namespace redb.Identity.Http.Processors;

/// <summary>
/// N7-1 — per-path scope guard for the management API. Runs after
/// <c>ManagementBearerAuthProcessor</c> has validated the bearer token and stashed
/// <c>identity:management-scopes</c>, and BEFORE <c>StripManagementPrefix</c> so the
/// raw <c>/api/v1/identity/{...}</c> path is still visible.
/// <para>
/// F5: the decision itself moved to Core, behind <c>direct-vm://identity-authz-check</c>, when a second
/// transport was about to need the same table. What is left here is the part that is genuinely about
/// HTTP — naming the resource and the action — and even that is a fallback: Core reads
/// <c>redbHttp.Path</c> and <c>redbHttp.Method</c> directly when nothing states them, so the path is not
/// carried twice and cannot drift from itself.
/// </para>
/// <para>
/// The rules are unchanged and live in <c>AuthorizationCheckProcessor</c>: anonymous short-circuit,
/// <c>identity:manage</c> bypass, <c>identity:account</c> self-service branch, read-only admin on
/// GET-class methods, per-prefix scopes with write implying read, and default-deny for anything unmapped.
/// </para>
/// </summary>
internal static class GranularScopeGuardProcessor
{
    /// <summary>
    /// Names the resource and action for the check that follows. Kept as a step of its own rather than
    /// folded into the route so the HTTP-specific half of the contract stays visible at the call site.
    /// </summary>
    internal static Task Describe(IExchange e, CancellationToken ct)
    {
        var path = e.In.GetHeader<string>("redbHttp.Path") ?? string.Empty;
        var method = (e.In.GetHeader<string>("redbHttp.Method") ?? "GET").ToUpperInvariant();

        e.Properties["identity:authz-resource"] = path;
        e.Properties["identity:authz-action"] = method is "GET" or "HEAD" or "OPTIONS" ? "read" : "write";

        return Task.CompletedTask;
    }
}
