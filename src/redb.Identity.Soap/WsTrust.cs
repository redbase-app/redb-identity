using System.Xml.Linq;

namespace redb.Identity.Soap;

/// <summary>
/// The WS-Trust vocabulary and the translation between it and what Core speaks.
/// <para>
/// Core takes form-encoded parameters, the same set on every transport: <c>grant_type</c>,
/// <c>client_id</c>, <c>token</c> and friends. WS-Trust says the same things in XML with different
/// names. This type is the whole of that translation, and it deliberately holds no logic beyond it: the
/// facade must not become a second authorization server.
/// </para>
/// </summary>
internal static class WsTrust
{
    public static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static readonly XNamespace Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static readonly XNamespace Wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public static readonly XNamespace Wsa = "http://www.w3.org/2005/08/addressing";

    /// <summary>The four request types this facade serves, by their WS-Trust URI suffix.</summary>
    public const string Issue = "Issue";
    public const string Validate = "Validate";
    public const string Cancel = "Cancel";
    public const string Renew = "Renew";

    /// <summary>Value type announcing that the carried token is a JWT, per RFC 8693's URN.</summary>
    public const string JwtValueType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>Encoding declared on a <c>BinarySecurityToken</c> whose content is base64.</summary>
    public const string Base64Encoding =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

    public const string StatusTokenType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
    public const string StatusValid = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/valid";
    public const string StatusInvalid = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/invalid";

    /// <summary>
    /// Names the operation. The WS-Addressing <c>Action</c> is the primary source because that is what
    /// the specification routes on and what generators emit; <c>wst:RequestType</c> inside the body is
    /// the fallback, because clients that omit the addressing header are common enough that failing
    /// them would be failing the audience this facade exists for.
    /// </summary>
    public static string? ResolveRequestType(string? action, XElement? rst)
    {
        var fromAction = LastSegment(action);
        if (IsKnown(fromAction)) return fromAction;

        var fromBody = LastSegment(rst?.Element(Wst + "RequestType")?.Value);
        return IsKnown(fromBody) ? fromBody : null;

        static bool IsKnown(string? value) =>
            value is Issue or Validate or Cancel or Renew;
    }

    /// <summary>Takes the trailing token of a slash-separated URI, which is where the verb lives.</summary>
    private static string? LastSegment(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return null;
        var trimmed = uri!.TrimEnd('/');
        var slash = trimmed.LastIndexOf('/');
        return slash < 0 ? trimmed : trimmed[(slash + 1)..];
    }

    /// <summary>Finds the <c>RequestSecurityToken</c> element, wherever the body put it.</summary>
    public static XElement? FindRst(XElement body) =>
        body.Name == Wst + "RequestSecurityToken"
            ? body
            : body.Descendants(Wst + "RequestSecurityToken").FirstOrDefault();

    /// <summary>
    /// Reads the token a request operates on. <c>Validate</c>, <c>Cancel</c> and <c>Renew</c> each name
    /// their target with a different element, and each wraps it in a security-token reference or carries
    /// it inline, so the search is for the first thing that looks like a token under the target.
    /// </summary>
    public static string? ReadTargetToken(XElement rst, string requestType)
    {
        var targetName = requestType switch
        {
            Validate => "ValidateTarget",
            Cancel => "CancelTarget",
            Renew => "RenewTarget",
            _ => null,
        };
        if (targetName is null) return null;

        var target = rst.Element(Wst + targetName);
        if (target is null) return null;

        // Inline BinarySecurityToken is the shape we emit ourselves, so it is the shape we read first.
        var binary = target.Descendants(Wsse + "BinarySecurityToken").FirstOrDefault();
        if (binary is not null) return Decode(binary);

        // Otherwise take the first non-empty text under the target: a bare token, or a reference whose
        // URI is the token itself. Anything more elaborate is a token store lookup we do not have.
        var text = target.DescendantsAndSelf()
            .Select(e => e.Value.Trim())
            .FirstOrDefault(v => v.Length > 0);

        return string.IsNullOrEmpty(text) ? null : text;
    }

    /// <summary>
    /// The scope being asked for. WS-Trust says this with <c>AppliesTo</c> carrying an endpoint
    /// reference; some stacks send a plain <c>wst:Scope</c>. Both are read, and neither is required.
    /// </summary>
    public static string? ReadScope(XElement rst)
    {
        var appliesTo = rst.Element(Wsp + "AppliesTo");
        var address = appliesTo?.Descendants(Wsa + "Address").FirstOrDefault()?.Value.Trim();
        if (!string.IsNullOrEmpty(address)) return address;

        var scope = rst.Element(Wst + "Scope")?.Value.Trim();
        return string.IsNullOrEmpty(scope) ? null : scope;
    }

    /// <summary>Base64 content of a <c>BinarySecurityToken</c>, or its raw text if it is not base64.</summary>
    private static string Decode(XElement binarySecurityToken)
    {
        var raw = binarySecurityToken.Value.Trim();
        var encoding = (string?)binarySecurityToken.Attribute("EncodingType");

        if (encoding is null || !encoding.EndsWith("Base64Binary", StringComparison.Ordinal))
            return raw;

        try { return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(raw)); }
        catch (FormatException) { return raw; }
    }

    // ── building the answer ──────────────────────────────────

    /// <summary>
    /// Builds the <c>Issue</c> and <c>Renew</c> answer: a response collection carrying the token.
    /// <para>
    /// The token is a JWT, declared as such by its value type, and base64-wrapped because that is what
    /// <c>BinarySecurityToken</c> means. Lifetime is emitted when the answer carried one: a client that
    /// caches tokens needs to know when to stop.
    /// </para>
    /// </summary>
    public static XElement BuildIssueResponse(string accessToken, long? expiresInSeconds, string? scope)
    {
        var token = new XElement(Wsse + "BinarySecurityToken",
            new XAttribute("ValueType", JwtValueType),
            new XAttribute("EncodingType", Base64Encoding),
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(accessToken)));

        var response = new XElement(Wst + "RequestSecurityTokenResponse",
            new XElement(Wst + "TokenType", JwtValueType),
            new XElement(Wst + "RequestedSecurityToken", token));

        if (expiresInSeconds is > 0)
        {
            var created = DateTimeOffset.UtcNow;
            response.Add(new XElement(Wst + "Lifetime",
                new XElement(Wsu + "Created", created.ToString("o")),
                new XElement(Wsu + "Expires", created.AddSeconds(expiresInSeconds.Value).ToString("o"))));
        }

        if (!string.IsNullOrEmpty(scope))
            response.Add(new XElement(Wst + "Scope", scope));

        return new XElement(Wst + "RequestSecurityTokenResponseCollection", response);
    }

    /// <summary>
    /// Builds the <c>Validate</c> answer. WS-Trust answers validation with a status code, not with the
    /// introspection document: a client asks «is this token good», and the verdict is the answer.
    /// </summary>
    public static XElement BuildStatusResponse(bool valid, string? reason = null)
    {
        var status = new XElement(Wst + "Status",
            new XElement(Wst + "Code", valid ? StatusValid : StatusInvalid));

        if (!valid && !string.IsNullOrEmpty(reason))
            status.Add(new XElement(Wst + "Reason", reason));

        return new XElement(Wst + "RequestSecurityTokenResponse",
            new XElement(Wst + "TokenType", StatusTokenType),
            status);
    }

    /// <summary>
    /// Builds the <c>Cancel</c> answer. RFC 7009 makes a well-formed revocation always successful, and
    /// WS-Trust says so with an empty element rather than a payload.
    /// </summary>
    public static XElement BuildCancelResponse() =>
        new(Wst + "RequestSecurityTokenResponse",
            new XElement(Wst + "RequestedTokenCancelled"));
}
