using redb.Identity.Contracts.Consents;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H3 (v1.0 DoD §6): self-service consent management backing
/// <c>GET /me/consents</c> and <c>DELETE /me/consents/{clientId}</c>. Returns the
/// caller's own valid permanent OAuth/OIDC consent grants and lets them revoke a
/// specific grant by <c>client_id</c>. Caller id is taken from the access token —
/// the request body never carries a userId.
/// </summary>
internal sealed class MeConsentsProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public MeConsentsProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var callerId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "invalid_token",
                $"The access token does not carry a numeric subject claim required for self-service APIs (got subject={MeProcessorHelpers.GetRawCallerSubject(exchange) ?? "<null>"}).");
            return;
        }

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        // Lazy resolution: input-validation paths (e.g. grant with empty clientId/scopes)
        // must reject before any IRouteContext access so they can be unit-tested without DI.
        ConsentService? consentService = null;
        ConsentService GetConsents() => consentService
            ??= new ConsentService(_context.GetRedbService(_redbName, exchange));

        switch (operation)
        {
            case "list":
                await List(GetConsents(), exchange, callerId.Value, ct);
                break;
            case "revoke":
                await Revoke(GetConsents(), exchange, callerId.Value, ct);
                break;
            case "grant":
                await Grant(GetConsents, exchange, callerId.Value, ct);
                break;
            default:
                MeProcessorHelpers.Reject(exchange, 400, "invalid_operation",
                    $"Unknown operation: {operation}");
                break;
        }
    }

    private static async Task Grant(
        Func<ConsentService> consentsFactory, IExchange exchange, long userId, CancellationToken ct)
    {
        // Body shape: typed GrantMyConsentRequest from the controller, or a route-supplied
        // dictionary with clientId + scopes (string[] or space-separated string) for direct-vm callers.
        string? clientId = null;
        IReadOnlyCollection<string>? scopes = null;

        switch (exchange.In.Body)
        {
            case GrantMyConsentRequest req:
                clientId = req.ClientId;
                scopes = req.Scopes;
                break;
            case IDictionary<string, object?> dict:
                if (dict.TryGetValue("clientId", out var cid))
                    clientId = cid?.ToString();
                if (dict.TryGetValue("scopes", out var sc))
                {
                    scopes = sc switch
                    {
                        string[] arr => arr,
                        IEnumerable<object?> en => en.Select(x => x?.ToString() ?? "")
                            .Where(s => !string.IsNullOrWhiteSpace(s)).ToArray(),
                        string spaceSep => spaceSep.Split(' ', StringSplitOptions.RemoveEmptyEntries),
                        _ => null
                    };
                }
                break;
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "ClientId is required");
            return;
        }
        if (scopes is null || scopes.Count == 0)
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "At least one scope is required");
            return;
        }

        var consents = consentsFactory();
        var applicationId = await consents.FindApplicationIdAsync(clientId, ct);
        if (applicationId is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found",
                $"Application with ClientId='{clientId}' not found.");
            return;
        }

        var auth = await consents.GrantAsync(userId, applicationId.Value, scopes, ct);

        exchange.Out ??= new Message();
        exchange.Out.Body = new
        {
            id = auth.id,
            userId,
            clientId,
            applicationId = applicationId.Value,
            scopes = auth.Props.Scopes ?? Array.Empty<string>()
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ConsentGranted;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            ClientId = clientId,
            ApplicationId = applicationId.Value,
            Scopes = string.Join(' ', scopes),
            SelfService = true
        };
    }

    private static async Task List(
        ConsentService consents, IExchange exchange, long userId, CancellationToken ct)
    {
        var grants = await consents.ListAsync(userId, ct);

        var response = grants.Select(c => new ConsentResponse
        {
            Id = c.Id,
            UserId = c.UserId,
            ApplicationId = c.ApplicationId,
            ClientId = c.ClientId,
            ApplicationName = c.ApplicationName,
            Scopes = c.Scopes,
            Status = "valid",
            CreatedAt = c.CreatedAt
        }).ToList();

        exchange.Out ??= new Message();
        exchange.Out.Body = response;
    }

    private static async Task Revoke(
        ConsentService consents, IExchange exchange, long userId, CancellationToken ct)
    {
        // Body shape: either MeRevokeConsentRequest, or a route-supplied dict with "clientId"
        // (the controller path-segment is mapped into the body for direct-vm dispatch).
        string? clientId = null;
        switch (exchange.In.Body)
        {
            case MeRevokeConsentRequest req:
                clientId = req.ClientId;
                break;
            case IDictionary<string, object?> dict
                when dict.TryGetValue("clientId", out var cid):
                clientId = cid?.ToString();
                break;
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "ClientId is required");
            return;
        }

        var applicationId = await consents.FindApplicationIdAsync(clientId, ct);
        if (applicationId is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found",
                $"Application with ClientId='{clientId}' not found.");
            return;
        }

        var revoked = await consents.RevokeAsync(userId, applicationId.Value, ct);

        exchange.Out ??= new Message();
        exchange.Out.Body = new { revoked };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ConsentRevoked;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            ClientId = clientId,
            ApplicationId = applicationId.Value,
            Count = revoked,
            SelfService = true
        };
    }
}

