using redb.Identity.Contracts.Audit;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H9 (v1.0 DoD): REST admin API for the identity audit log.
/// Forwards to <c>direct-vm://identity-manage-audit</c> route.
/// </summary>
[Route("audit")]
public class AuditController : IdentityControllerBase
{
    /// <summary>
    /// Queries the audit log. All filters are optional and ANDed together.
    /// Results are ordered newest-first; page size is clamped to [1..500] server-side.
    /// </summary>
    [HttpGet]
    public async Task<object?> Query(
        [FromQuery("eventType")] string? eventType = null,
        [FromQuery("category")] string? category = null,
        [FromQuery("userId")] string? userId = null,
        [FromQuery("login")] string? login = null,
        [FromQuery("clientId")] string? clientId = null,
        [FromQuery("from")] string? from = null,
        [FromQuery("to")] string? to = null,
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 50)
    {
        var request = new AuditQueryRequest
        {
            EventType = eventType,
            Category = category,
            UserId = userId,
            Login = login,
            ClientId = clientId,
            From = TryParseIso(from),
            To = TryParseIso(to),
            Offset = offset,
            Count = count
        };

        return await Forward(IdentityEndpoints.ManageAudit, operation: "query", request);
    }

    private static DateTimeOffset? TryParseIso(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        return DateTimeOffset.TryParse(s, out var dto) ? dto : null;
    }
}
