using redb.Identity.Contracts.Consents;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Management processor for user consents.
/// Dispatches on the "operation" header: list, revoke, revoke-all.
/// </summary>
internal sealed class ConsentManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ConsentManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var consent = new ConsentService(redb);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "list":
                await List(consent, exchange, ct);
                break;
            case "revoke":
                await Revoke(consent, exchange, ct);
                break;
            case "revoke-all":
                await RevokeAll(consent, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private static async Task List(ConsentService consent, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var consents = await consent.ListAsync(userId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = consents.Select(c => new ConsentResponse
        {
            Id = c.Id, UserId = c.UserId, ApplicationId = c.ApplicationId,
            ClientId = c.ClientId, ApplicationName = c.ApplicationName,
            Scopes = c.Scopes, Status = "valid", CreatedAt = c.CreatedAt
        }).ToList();
    }

    private static async Task Revoke(ConsentService consent, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?>
            ?? throw new InvalidOperationException("Body is required");
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var appId = IdentityProcessorHelpers.ExtractLong(dict, "applicationId")
            ?? throw new InvalidOperationException("applicationId is required");
        var revoked = await consent.RevokeAsync(userId, appId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, revoked };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ConsentRevoked;
        exchange.Properties["identity-event-data"] = new { UserId = userId, ApplicationId = appId };
    }

    private static async Task RevokeAll(ConsentService consent, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var revoked = await consent.RevokeAllAsync(userId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, revoked };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.AllConsentsRevoked;
        exchange.Properties["identity-event-data"] = new { UserId = userId };
    }
}
