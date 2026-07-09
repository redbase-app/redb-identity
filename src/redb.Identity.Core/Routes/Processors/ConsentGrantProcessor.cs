using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Processes user consent approval. Expects body with: userId, clientId, scopes (space-separated).
/// Grants consent via <see cref="ConsentService"/> and signals success.
/// </summary>
internal sealed class ConsentGrantProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ConsentGrantProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);

        var body = exchange.In.Body as IDictionary<string, object?>;
        if (body is null)
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request", "Request body is required");
            return;
        }

        var userId = IdentityProcessorHelpers.ExtractLong(
            body as Dictionary<string, object?> ?? new(body), "userId") ?? 0;
        body.TryGetValue("clientId", out var cidObj);
        var clientId = cidObj?.ToString();
        body.TryGetValue("scopes", out var scopesObj);
        var scopesStr = scopesObj?.ToString() ?? "";

        if (userId <= 0)
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request", "userId is required");
            return;
        }

        if (string.IsNullOrEmpty(clientId))
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request", "clientId is required");
            return;
        }

        var consentService = new ConsentService(redb);
        var appId = await consentService.FindApplicationIdAsync(clientId).ConfigureAwait(false);
        if (appId is null or <= 0)
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_client", "Unknown client_id");
            return;
        }

        var scopes = scopesStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        await consentService.GrantAsync(userId, appId.Value, scopes).ConfigureAwait(false);

        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["userId"] = userId,
            ["clientId"] = clientId,
            ["scopes"] = scopesStr
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ConsentGranted;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            ClientId = clientId,
            Scopes = scopesStr
        };
    }
}
