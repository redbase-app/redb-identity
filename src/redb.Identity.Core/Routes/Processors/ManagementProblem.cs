using redb.Identity.Core.Serialization;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// The one refusal every authorization gate on the management surface produces.
/// <para>
/// A single generic <c>403</c> Problem Details answer (RFC 9457) with the stable machine-readable
/// <c>code</c> <c>not_authorized</c>. Every gate uses the same shape on purpose: the answer must not
/// tell the caller whether the target exists, which rule refused, or whether a context was missing or
/// merely insufficient — B8 (IDOR) rests on that. This is an application-level authorization rule, not
/// an RFC 6750 scope challenge: the 6750 challenge, when there is one, was already issued upstream by
/// <see cref="ManagementBearerAuthProcessor"/>.
/// </para>
/// </summary>
internal static class ManagementProblem
{
    public const string Code = "not_authorized";

    /// <summary>Refuses the exchange: 403 problem body, handled exception, route stopped.</summary>
    public static void Forbidden(IExchange exchange, string detail)
    {
        var problem = new Dictionary<string, object?>
        {
            ["type"] = "https://redb.local/problems/authorization-denied",
            ["title"] = "Forbidden",
            ["status"] = 403,
            ["detail"] = detail,
            ["code"] = Code,
        };

        // Serialize through the locked Problem profile facade: the same wire format a registry lookup
        // for "application/problem+json" returns (IdentityCodecProfilesConfigurator); the gates have no
        // route context to look it up with, and the profile is an Identity-owned, RFC-locked artifact.
        var body = IdentityCodecProfiles.Problem.Serialize(problem);
        exchange.Out = new Message(body);
        // Core-level content type keeps the value transport-agnostic for the Rabbit/Kafka facades.
        exchange.Out.ContentType = IdentityCodecProfiles.ProblemMediaType;
        exchange.Out.Headers["redbHttp.ResponseCode"] = 403;
        exchange.Out.Headers["redbHttp.ResponseContentType"] = IdentityCodecProfiles.ProblemMediaType;
        exchange.Exception = new UnauthorizedAccessException(detail);
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }
}
