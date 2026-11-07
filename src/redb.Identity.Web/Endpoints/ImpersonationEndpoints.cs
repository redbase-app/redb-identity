using System.Security.Claims;
using System.Text.Json;
using redb.Identity.Client;
using redb.Identity.Web.Auth;

namespace redb.Identity.Web.Endpoints;

/// <summary>
/// N7-3 — BFF endpoints for admin impersonation overlay.
/// <para>
/// Flow: admin (with the <c>identity.impersonate</c> policy) calls
/// <c>POST /api/auth/impersonate/start/{userId}</c>. The BFF forwards to the Identity API
/// (writing an audit event), then drops a signed cookie holding the impersonation target.
/// The cookie is read on every page render to drive the banner and to scope admin pages
/// to the target user.
/// </para>
/// <para>
/// Stopping the overlay reverses the cookie and writes a corresponding audit event.
/// </para>
/// </summary>
public static class ImpersonationEndpoints
{
    public static void MapImpersonationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/auth/impersonate/start/{userId:long}", StartAsync)
            .RequireAuthorization("identity.impersonate");

        app.MapPost("/api/auth/impersonate/stop", StopAsync)
            .RequireAuthorization("identity.impersonate");
    }

    private static async Task<IResult> StartAsync(
        long userId,
        HttpContext ctx,
        IIdentityClient identity,
        ImpersonationStateProtector protector,
        [Microsoft.AspNetCore.Mvc.FromQuery] string? reason = null,
        CancellationToken ct = default)
    {
        if (userId <= 0)
        {
            return Results.BadRequest(new { error = "invalid_user_id" });
        }

        JsonElement apiResponse;
        try
        {
            apiResponse = await identity.StartImpersonationAsync(userId, reason, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return Results.Problem(detail: ex.Message, statusCode: 502, title: "impersonation_api_failed");
        }

        // Identity API returns either { targetUserId, targetLogin } or { error, error_description }.
        if (apiResponse.ValueKind == JsonValueKind.Object && apiResponse.TryGetProperty("error", out var errProp))
        {
            return Results.BadRequest(new
            {
                error = errProp.GetString(),
                error_description = apiResponse.TryGetProperty("error_description", out var d) ? d.GetString() : null
            });
        }

        var targetId = apiResponse.TryGetProperty("targetUserId", out var tid) && tid.TryGetInt64(out var t) ? t : userId;
        var targetLogin = apiResponse.TryGetProperty("targetLogin", out var tl) ? (tl.GetString() ?? string.Empty) : string.Empty;

        var adminSubject = ctx.User.FindFirstValue("sub")
                         ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? string.Empty;

        var overlay = new ImpersonationOverlay(targetId, targetLogin, adminSubject, DateTimeOffset.UtcNow);
        protector.WriteCookie(ctx, overlay);

        return Results.Ok(new { targetUserId = targetId, targetLogin });
    }

    private static async Task<IResult> StopAsync(
        HttpContext ctx,
        IIdentityClient identity,
        ImpersonationStateProtector protector,
        CancellationToken ct = default)
    {
        var overlay = protector.ReadCookie(ctx);
        if (overlay is null)
        {
            // Idempotent: nothing to stop.
            return Results.Ok(new { stopped = true });
        }

        try
        {
            await identity.StopImpersonationAsync(overlay.TargetUserId, ct).ConfigureAwait(false);
        }
        catch
        {
            // Audit-only call — never block stop on a transient API failure.
        }

        protector.ClearCookie(ctx);
        return Results.Ok(new { stopped = true });
    }
}
