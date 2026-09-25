using redb.Identity.Contracts;
using redb.Route.Soap;

namespace redb.Identity.Soap;

/// <summary>
/// Refusals, in the vocabulary WS-Trust clients read.
/// <para>
/// This is the third transport that must say what the identity core decided, and the plan flagged the
/// risk of it becoming a third independent copy of the translation. It is not: the reading of the core's
/// verdict lives once, in <see cref="IdentityVerdict"/>, and what remains here is the rendering of that
/// verdict into WS-Trust's own fault codes. Nothing in this file decides whether a request is allowed.
/// </para>
/// <para>
/// A fault is not an optional nicety. A client that receives a successful response carrying an error
/// document has no reason to look inside it, and generated WS-Trust clients branch on the fault code:
/// <c>FailedAuthentication</c> and <c>InvalidRequest</c> are different outcomes to them.
/// </para>
/// <para>
/// What reaches the wire is one thing; what it means for the route is another, and this file says both.
/// A <see cref="WsTrustRefusal"/> is the STS doing its job — the request was malformed, the caller could
/// not authenticate, the scope is not theirs, they are over the rate limit — and it leaves as the STS's
/// answer, with the exchange successful. A <see cref="SoapFaultException"/> from <see cref="Server"/> is
/// our side breaking, and it leaves as a failure the route's error count and dead-letter channel see.
/// </para>
/// </summary>
internal static class Fault
{
    private const string Wst = "wst:";

    /// <summary>The caller could not be authenticated, or the grant was refused.</summary>
    public static WsTrustRefusal FailedAuthentication(string reason) =>
        new(Wst + "FailedAuthentication", reason);

    /// <summary>The request is malformed or missing something WS-Trust requires.</summary>
    public static WsTrustRefusal InvalidRequest(string reason) =>
        new(Wst + "InvalidRequest", reason);

    /// <summary>The scope asked for is not one this caller may have.</summary>
    public static WsTrustRefusal InvalidScope(string reason) =>
        new(Wst + "InvalidScope", reason);

    /// <summary>
    /// The caller is over the rate limit. WS-Trust has no code for it, and <c>soap:Server</c> is the closer
    /// of the two available readings — the caller must wait, not rewrite the request. It is still an
    /// answer, not a failure: throttling is the limiter working, the same way the HTTP facade's 429 is.
    /// </summary>
    public static WsTrustRefusal Throttled(string reason) =>
        new("soap:Server", reason);

    /// <summary>Our side failed. The reason stays plain: internals are not the caller's business.</summary>
    public static SoapFaultException Server(string reason) =>
        new("soap:Server", reason);

    /// <summary>
    /// Renders the core's verdict as the fault WS-Trust has for it.
    /// <para>
    /// WS-Trust names far fewer outcomes than HTTP does, so several verdicts land on one fault. Where
    /// they do, the reason text carries what the code cannot, which is why it is never dropped.
    /// </para>
    /// </summary>
    public static Exception FromVerdict(IdentityVerdictKind kind, string reason) => kind switch
    {
        IdentityVerdictKind.Unauthenticated or IdentityVerdictKind.Forbidden
            => FailedAuthentication(reason),

        IdentityVerdictKind.InvalidScope => InvalidScope(reason),

        IdentityVerdictKind.RateLimited => Throttled(reason),

        IdentityVerdictKind.Unavailable or IdentityVerdictKind.Timeout or IdentityVerdictKind.ServerError
            => Server(reason),

        // Everything left describes a request that cannot be served as written.
        _ => InvalidRequest(reason),
    };
}

/// <summary>
/// A WS-Trust fault the STS means as its answer. Raised wherever a step finds the request cannot be
/// served, and turned into the reply at the step's boundary — never allowed to fail the exchange.
/// </summary>
internal sealed class WsTrustRefusal : Exception
{
    public WsTrustRefusal(string faultCode, string faultString)
        : base($"WS-Trust refusal: {faultCode} — {faultString}")
    {
        FaultCode = faultCode;
        FaultString = faultString;
    }

    /// <summary>The code the caller branches on, e.g. <c>wst:InvalidRequest</c>.</summary>
    public string FaultCode { get; }

    /// <summary>The reason, carrying whatever the code cannot.</summary>
    public string FaultString { get; }
}
