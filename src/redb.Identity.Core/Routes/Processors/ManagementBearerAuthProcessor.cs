using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using redb.Identity.Core.Serialization;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Validates management API requests using OAuth2 Bearer token authentication.
/// Uses OpenIddict Validation (server-local, no network round-trip) to validate tokens
/// and checks for the required management scope.
/// </summary>
internal sealed class ManagementBearerAuthProcessor : IProcessor
{
    /// <summary>
    /// Transaction property key used to pass the bearer token to the OpenIddict Validation pipeline.
    /// </summary>
    internal const string TokenPropertyKey = "__mgmt_bearer_token";

    private readonly IOpenIddictValidationFactory _factory;
    private readonly IOpenIddictValidationDispatcher _dispatcher;
    private readonly string[] _acceptableScopes;
    private readonly string[] _anonymousPathPrefixes;

    /// <summary>
    /// Constructs the processor with a single required scope. The token must carry exactly
    /// this scope.
    /// </summary>
    public ManagementBearerAuthProcessor(
        IOpenIddictValidationFactory factory,
        IOpenIddictValidationDispatcher dispatcher,
        string requiredScope,
        IEnumerable<string>? anonymousPathPrefixes = null)
        : this(factory, dispatcher, new[] { requiredScope ?? throw new ArgumentNullException(nameof(requiredScope)) }, anonymousPathPrefixes)
    {
    }

    /// <summary>
    /// Constructs the processor with a set of acceptable scopes. The token must carry AT LEAST
    /// ONE of these scopes (any-of). Used to admit both administrator (e.g. <c>identity:manage</c>)
    /// and self-service (e.g. <c>identity:account</c>) callers; the subsequent
    /// <see cref="RequireSelfOrAdminProcessor"/> enforces the actual self-vs-admin rule.
    /// </summary>
    /// <param name="anonymousPathPrefixes">
    /// N-4 (Session C): optional list of URL path prefixes (matched against <c>redbHttp.Path</c>,
    /// case-insensitive) that bypass bearer-token validation entirely. Used for genuinely
    /// anonymous self-service endpoints (e.g. <c>/api/v1/identity/password/forgot</c>,
    /// <c>/api/v1/identity/password/reset</c>) that must be reachable without any prior
    /// authentication. When a request matches, the processor short-circuits without
    /// reading the Authorization header and without populating any
    /// <c>identity:management-*</c> properties — downstream processors MUST tolerate the
    /// absence of a principal.
    /// </param>
    public ManagementBearerAuthProcessor(
        IOpenIddictValidationFactory factory,
        IOpenIddictValidationDispatcher dispatcher,
        IEnumerable<string> acceptableScopes,
        IEnumerable<string>? anonymousPathPrefixes = null)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        if (acceptableScopes is null) throw new ArgumentNullException(nameof(acceptableScopes));
        _acceptableScopes = acceptableScopes.Where(s => !string.IsNullOrEmpty(s)).Distinct(StringComparer.Ordinal).ToArray();
        if (_acceptableScopes.Length == 0)
            throw new ArgumentException("At least one acceptable scope must be provided.", nameof(acceptableScopes));
        _anonymousPathPrefixes = (anonymousPathPrefixes ?? Array.Empty<string>())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .ToArray();
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        // N-4 (Session C): anonymous-prefix short-circuit. Genuinely public endpoints
        // (password-recovery flows) must be reachable without any Authorization header
        // at all — they live under the same /api/v1/identity/ root for URL stability
        // and dispatch through the same controller registry, but skip bearer validation
        // entirely here. Downstream processors / controllers MUST tolerate the absence
        // of `identity:management-principal`.
        if (_anonymousPathPrefixes.Length > 0)
        {
            var path = exchange.In.GetHeader<string>("redbHttp.Path");
            if (!string.IsNullOrEmpty(path))
            {
                System.Diagnostics.Debug.WriteLine($"[SCIM-AUTH] Path: {path}, Prefixes: {string.Join(", ", _anonymousPathPrefixes)}");
                foreach (var prefix in _anonymousPathPrefixes)
                {
                    if (path!.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        System.Diagnostics.Debug.WriteLine($"[SCIM-AUTH] MATCH: {path} starts with {prefix}");
                        exchange.Properties["identity:management-anonymous"] = true;
                        return;
                    }
                }
                System.Diagnostics.Debug.WriteLine($"[SCIM-AUTH] NO MATCH for {path}");
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[SCIM-AUTH] redbHttp.Path is empty/null");
            }
        }

        // 1. Extract bearer token from Authorization header.
        // D6: per RFC 6750 §2.1 the scheme token is case-insensitive ("Bearer", "bearer",
        // "BEARER" all valid) and per RFC 7230 §3.2.4 one-or-more SP / OWS is permitted
        // between the scheme and the credentials.
        var token = TryExtractBearerToken(exchange.In.GetHeader<string>("Authorization"));
        if (token is null)
        {
            Reject(exchange, 401, "missing_token",
                "Authorization header with Bearer token is required.");
            return;
        }

        if (token.Length == 0)
        {
            Reject(exchange, 401, "invalid_token", "Bearer token is empty.");
            return;
        }

        // 2. Validate token via OpenIddict Validation (server-local)
        var transaction = await _factory.CreateTransactionAsync();
        transaction.Properties[TokenPropertyKey] = token;
        transaction.CancellationToken = ct;

        var context = new OpenIddictValidationEvents.ProcessAuthenticationContext(transaction);
        await _dispatcher.DispatchAsync(context);

        if (context.IsRejected || context.AccessTokenPrincipal is null)
        {
            Reject(exchange, 401, context.Error ?? "invalid_token",
                context.ErrorDescription ?? "The access token is not valid.");
            return;
        }

        // 3. Check required scope
        var principal = context.AccessTokenPrincipal;
        var scopes = principal.GetScopes();

        if (!_acceptableScopes.Any(s => scopes.Contains(s, StringComparer.Ordinal)))
        {
            Reject(exchange, 403, "insufficient_scope",
                $"The access token does not have any of the required scopes: {string.Join(", ", _acceptableScopes)}.");
            return;
        }

        // 4. Store validated principal for downstream processors
        exchange.Properties["identity:management-principal"] = principal;
        exchange.Properties["identity:management-subject"] = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        // Mirror the internal bigint user id (if present — only end-user grants emit it,
        // client_credentials tokens carry only the public string sub). Self-service
        // processors read this property instead of long-parsing the GUID sub.
        var internalUid = principal.GetClaim(IdentityPrincipalBuilder.InternalUserIdClaim);
        if (!string.IsNullOrEmpty(internalUid) && long.TryParse(internalUid, out var uid) && uid > 0)
            exchange.Properties["identity:management-user-id"] = uid;
        // B8: surface the granted scopes so RequireSelfOrAdminProcessor can pick admin vs self.
        exchange.Properties["identity:management-scopes"] = scopes.ToArray();
        // H3-SSO: surface the "sid" claim (OIDC session id, written by
        // AttachSessionPrincipalHandler) so /me/sessions revoke-current can map the
        // current access token back to its owning session without trusting the body.
        // Only present on tokens issued via the OIDC session flow; client_credentials
        // and other grants won't have it — that's fine, revoke-current is a no-op for them.
        var sid = principal.GetClaim("sid");
        if (!string.IsNullOrEmpty(sid))
            exchange.Properties["identity:management-sid"] = sid;
    }

    private static void Reject(IExchange exchange, int statusCode, string error, string description)
    {
        // RFC 6749 §5.2 — OAuth 2.0 error response: application/json with snake_case
        // members "error", "error_description". RFC 6750 §3 mandates the same envelope
        // on protected-resource 401/403 responses so external OAuth clients (that a user
        // might point at our identity server as a drop-in replacement) can parse it.
        //
        // Going through the locked OAuthJson IMessageSerializer facade (rather than
        // raw JsonSerializer) keeps the wire format observably identical to what the
        // codec registry would produce, while guaranteeing that no app-level
        // `ConfigureJsonCodec(...)` can reshape this RFC-mandated payload — the OAuth
        // profile is intentionally NOT registered into IDataFormatRegistry.
        var body = IdentityCodecProfiles.OAuthJson.Serialize(new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        });
        exchange.Out = new Message(body);
        // Core-level content type keeps the value transport-agnostic for Rabbit/Kafka façades.
        exchange.Out.ContentType = IdentityCodecProfiles.OAuthMediaType;
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
        exchange.Out.Headers["redbHttp.ResponseContentType"] = IdentityCodecProfiles.OAuthMediaType;

        // D6: RFC 6750 §3.1 — challenge MUST be returned on 401 and SHOULD be returned
        // on 403 (insufficient_scope). The realm parameter helps clients distinguish
        // protected resources behind the same hostname.
        if (statusCode is 401 or 403)
        {
            exchange.Out.Headers["WWW-Authenticate"] = BuildChallenge(error, description);
        }

        exchange.Exception = new UnauthorizedAccessException(description);
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }

    private static string BuildChallenge(string error, string description)
    {
        // RFC 6750 §3 quoted-string syntax: backslash and double quotes must be escaped.
        var safeDesc = description.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var safeError = error.Replace("\\", "\\\\").Replace("\"", "\\\"");
        return $"Bearer realm=\"identity\", error=\"{safeError}\", error_description=\"{safeDesc}\"";
    }

    /// <summary>
    /// Parses a single <c>Authorization: Bearer &lt;token&gt;</c> header tolerantly per
    /// RFC 6750 §2.1 + RFC 7230 §3.2.4. Returns the raw token (possibly empty), or
    /// <c>null</c> when the header is absent / does not use the Bearer scheme.
    /// </summary>
    internal static string? TryExtractBearerToken(string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(authorizationHeader))
            return null;

        var span = authorizationHeader.AsSpan().TrimStart();
        const string scheme = "Bearer";
        if (span.Length < scheme.Length ||
            !span[..scheme.Length].Equals(scheme.AsSpan(), StringComparison.OrdinalIgnoreCase))
            return null;

        var after = span[scheme.Length..];

        // Must be at least one whitespace separator (or empty rest, which we treat
        // as empty token below).
        if (after.Length > 0 && after[0] != ' ' && after[0] != '\t')
            return null;

        return after.Trim().ToString();
    }
}
