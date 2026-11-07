using System.Text.Json;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// A single entry of the OIDC <c>claims</c> request parameter (OpenID Connect Core 1.0 §5.5.1):
/// <c>{"name": null}</c>, <c>{"name": {"essential": true}}</c>,
/// <c>{"sub": {"value": "..."}}</c> or <c>{"acr": {"values": ["1","2"]}}</c>.
/// </summary>
public sealed class OidcClaimsRequestEntry
{
    /// <summary>
    /// §5.5.1 — the RP marks the claim as Essential: it needs the claim to serve the End-User.
    /// A voluntary claim (the default, and what <c>null</c> means) is a nice-to-have. Note the
    /// spec is explicit that "essential" does NOT make the claim mandatory for the OP to return —
    /// it must still be omitted when we simply do not hold a value for this user.
    /// </summary>
    public bool Essential { get; init; }

    /// <summary>§5.5.1 — the RP requests this exact value for the claim.</summary>
    public string? Value { get; init; }

    /// <summary>§5.5.1 — the RP will accept any one of these values.</summary>
    public IReadOnlyList<string>? Values { get; init; }

    /// <summary>
    /// Whether a value we hold satisfies the RP's <c>value</c> / <c>values</c> constraint.
    /// When neither is present, every value is acceptable (the RP just asked for the claim).
    /// A constrained request that we cannot satisfy means we must NOT return the claim — the
    /// RP asked for a specific value, and sending a different one would be a lie, not a
    /// best-effort answer.
    /// </summary>
    public bool Accepts(string? actual)
    {
        if (string.IsNullOrEmpty(actual)) return false;
        if (Value is not null) return string.Equals(Value, actual, StringComparison.Ordinal);
        if (Values is { Count: > 0 }) return Values.Contains(actual, StringComparer.Ordinal);
        return true;
    }
}

/// <summary>
/// The parsed OIDC <c>claims</c> request parameter (OpenID Connect Core 1.0 §5.5) — the RP's
/// per-claim request, as opposed to the coarse per-scope request.
/// <para>
/// Two top-level members are meaningful: <c>userinfo</c> (deliver via /connect/userinfo) and
/// <c>id_token</c> (embed in the id_token). §5.5 allows other members to be defined by
/// extensions; we ignore what we do not understand rather than rejecting the request, because
/// rejecting would break an RP that added a member some other OP understands.
/// </para>
/// <para>
/// This type is protocol-only: it is a parse of one request parameter and is never persisted.
/// It carries no storage concern and no HTTP concern — the HTTP layer is a façade that maps the
/// query string into the exchange body; the meaning of <c>claims</c> is decided here, in Core.
/// </para>
/// </summary>
public sealed class OidcClaimsRequest
{
    private static readonly IReadOnlyDictionary<string, OidcClaimsRequestEntry> Empty
        = new Dictionary<string, OidcClaimsRequestEntry>(StringComparer.Ordinal);

    private OidcClaimsRequest(
        IReadOnlyDictionary<string, OidcClaimsRequestEntry> idToken,
        IReadOnlyDictionary<string, OidcClaimsRequestEntry> userInfo)
    {
        IdToken = idToken;
        UserInfo = userInfo;
    }

    /// <summary>Claims the RP asked to have embedded in the id_token.</summary>
    public IReadOnlyDictionary<string, OidcClaimsRequestEntry> IdToken { get; }

    /// <summary>Claims the RP asked to be able to fetch from /connect/userinfo.</summary>
    public IReadOnlyDictionary<string, OidcClaimsRequestEntry> UserInfo { get; }

    /// <summary>True when the parameter carried nothing we act on.</summary>
    public bool IsEmpty => IdToken.Count == 0 && UserInfo.Count == 0;

    /// <summary>
    /// Parses the raw <c>claims</c> parameter. Returns false with an <paramref name="error"/>
    /// suitable for an <c>invalid_request</c> description when the value is not a JSON object of
    /// the shape §5.5 defines. A malformed <c>claims</c> parameter is a client bug and must be
    /// reported as such — silently ignoring it would leave the RP believing it asked for claims
    /// that it will never receive.
    /// </summary>
    public static bool TryParse(string? raw, out OidcClaimsRequest? request, out string? error)
    {
        request = null;
        error = null;

        if (string.IsNullOrWhiteSpace(raw))
        {
            request = new OidcClaimsRequest(Empty, Empty);
            return true;
        }

        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            root = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            error = $"The 'claims' parameter is not valid JSON: {ex.Message}";
            return false;
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            error = "The 'claims' parameter must be a JSON object (OpenID Connect Core 1.0 §5.5).";
            return false;
        }

        if (!TryParseMember(root, "id_token", out var idToken, out error)) return false;
        if (!TryParseMember(root, "userinfo", out var userInfo, out error)) return false;

        request = new OidcClaimsRequest(idToken, userInfo);
        return true;
    }

    private static bool TryParseMember(
        JsonElement root, string member,
        out IReadOnlyDictionary<string, OidcClaimsRequestEntry> entries, out string? error)
    {
        entries = Empty;
        error = null;

        if (!root.TryGetProperty(member, out var element)) return true;

        // §5.5 — the member may be explicitly null, meaning "nothing requested here".
        if (element.ValueKind == JsonValueKind.Null) return true;

        if (element.ValueKind != JsonValueKind.Object)
        {
            error = $"The '{member}' member of the 'claims' parameter must be a JSON object.";
            return false;
        }

        var map = new Dictionary<string, OidcClaimsRequestEntry>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!TryParseEntry(property, member, out var entry, out error)) return false;
            map[property.Name] = entry!;
        }

        entries = map;
        return true;
    }

    private static bool TryParseEntry(
        JsonProperty property, string member,
        out OidcClaimsRequestEntry? entry, out string? error)
    {
        entry = null;
        error = null;

        // §5.5 — `null` requests the claim as Voluntary. This is the common case:
        // {"userinfo": {"email": null}}.
        if (property.Value.ValueKind == JsonValueKind.Null)
        {
            entry = new OidcClaimsRequestEntry();
            return true;
        }

        if (property.Value.ValueKind != JsonValueKind.Object)
        {
            error = $"Claim '{property.Name}' in '{member}' must be null or a JSON object.";
            return false;
        }

        var essential = false;
        if (property.Value.TryGetProperty("essential", out var essentialElement))
        {
            if (essentialElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                error = $"'essential' for claim '{property.Name}' must be a JSON boolean.";
                return false;
            }
            essential = essentialElement.GetBoolean();
        }

        string? value = null;
        if (property.Value.TryGetProperty("value", out var valueElement)
            && valueElement.ValueKind != JsonValueKind.Null)
        {
            value = ScalarToString(valueElement);
            if (value is null)
            {
                error = $"'value' for claim '{property.Name}' must be a JSON string, number or boolean.";
                return false;
            }
        }

        List<string>? values = null;
        if (property.Value.TryGetProperty("values", out var valuesElement)
            && valuesElement.ValueKind != JsonValueKind.Null)
        {
            if (valuesElement.ValueKind != JsonValueKind.Array)
            {
                error = $"'values' for claim '{property.Name}' must be a JSON array.";
                return false;
            }

            values = new List<string>();
            foreach (var item in valuesElement.EnumerateArray())
            {
                var scalar = ScalarToString(item);
                if (scalar is null)
                {
                    error = $"'values' for claim '{property.Name}' must contain scalars only.";
                    return false;
                }
                values.Add(scalar);
            }
        }

        entry = new OidcClaimsRequestEntry { Essential = essential, Value = value, Values = values };
        return true;
    }

    /// <summary>
    /// Renders a JSON scalar the way the corresponding claim is stored on the principal, so that
    /// <see cref="OidcClaimsRequestEntry.Accepts"/> compares like with like. Claims live on a
    /// <c>ClaimsIdentity</c> as strings regardless of their JSON type, so a request for
    /// <c>{"email_verified": {"value": true}}</c> has to be matched against the string "true".
    /// </summary>
    private static string? ScalarToString(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number => element.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => null
    };
}
