using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// N7-3 — admin impersonation overlay.
/// <para>
/// Does NOT mint a token. The BFF tracks the impersonation target in its own session
/// cookie; this processor only validates the target user exists and emits an audit
/// event so the action is permanently recorded against the admin's <c>sub</c>.
/// </para>
/// <para>
/// Operations on the <c>operation</c> header:
/// <list type="bullet">
///   <item><c>start</c> — body <c>{ userId, reason? }</c>; returns <c>{ targetUserId, targetLogin }</c>.</item>
///   <item><c>stop</c> — body <c>{ userId }</c>; returns <c>{ stopped: true }</c>.</item>
/// </list>
/// </para>
/// </summary>
internal sealed class ImpersonationManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ImpersonationManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        var redb = _context.GetRedbService(_redbName, exchange);

        switch (operation)
        {
            case "start":
                await Start(redb, exchange, ct);
                break;
            case "stop":
                await Stop(redb, exchange, ct);
                break;
            default:
                exchange.Out ??= new Message();
                exchange.Out.Body = new
                {
                    error = "invalid_operation",
                    error_description = $"Unknown operation: {operation}"
                };
                break;
        }
    }

    private static async Task Start(redb.Core.IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var targetId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var reason = (exchange.In.Body as Dictionary<string, object?>) is { } dict
            ? dict.TryGetValue("reason", out var r) ? r as string : null
            : null;

        var target = await redb.UserProvider.GetUserByIdAsync(targetId);
        if (target is null)
        {
            exchange.Out ??= new Message();
            exchange.Out.Body = new
            {
                error = "not_found",
                error_description = $"User {targetId} not found"
            };
            return;
        }

        var adminSubject = exchange.Properties.TryGetValue("identity:management-subject", out var s) ? s as string : null;

        exchange.Out ??= new Message();
        exchange.Out.Body = new
        {
            targetUserId = target.Id,
            targetLogin = target.Login
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserImpersonationStarted;
        exchange.Properties["identity-event-data"] = new
        {
            AdminSubject = adminSubject,
            TargetUserId = target.Id,
            TargetLogin = target.Login,
            Reason = reason
        };
    }

    private static Task Stop(redb.Core.IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var targetId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var adminSubject = exchange.Properties.TryGetValue("identity:management-subject", out var s) ? s as string : null;

        exchange.Out ??= new Message();
        exchange.Out.Body = new { stopped = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserImpersonationStopped;
        exchange.Properties["identity-event-data"] = new
        {
            AdminSubject = adminSubject,
            TargetUserId = targetId
        };

        return Task.CompletedTask;
    }
}
