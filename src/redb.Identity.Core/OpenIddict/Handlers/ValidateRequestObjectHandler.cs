using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z7 (RFC 9101) — JWT-Secured Authorization Request. Accepts a signed <c>request</c> object on
/// <c>/connect/authorize</c>, verifies it against the client's published keys, and replaces the
/// request parameters with the ones carried inside the JWT.
/// <para>
/// This handler <b>replaces</b> OpenIddict's built-in <c>ValidateRequestParameter</c> /
/// <c>ValidateRequestUriParameter</c>, which unconditionally reject those parameters (6.3.0 has no
/// request-object support at all). Removal happens in <c>RedbRouteOpenIddictServerConfiguration</c>.
/// </para>
/// <para>
/// <b>With <c>Features.EnableJar = false</c> the observable behaviour is identical to before:</b>
/// a <c>request</c> parameter is rejected with <c>request_not_supported</c>. The flag adds a code
/// path; it does not change the default answer.
/// </para>
/// <para>
/// Parameter precedence follows RFC 9101 §6.1 — values inside the request object win, and outside
/// values that are not repeated inside are ignored. OIDC additionally requires <c>response_type</c>
/// and <c>client_id</c> to appear as plain parameters, which is what lets us find the client (and
/// therefore its keys) before we can trust anything in the JWT.
/// </para>
/// </summary>
internal sealed class ValidateRequestObjectHandler
    : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    /// <summary>PAR issues request_uri values with this prefix; those are handled by OpenIddict, not here.</summary>
    private const string ParRequestUriPrefix = "urn:ietf:params:oauth:request_uri:";

    private readonly IOpenIddictApplicationManager _applications;
    private readonly IClientKeyResolver _keyResolver;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly RedbIdentityOptions _identityOptions;
    private readonly ILogger<ValidateRequestObjectHandler> _logger;

    /// <summary>Named <see cref="HttpClient"/> used to fetch a <c>request_uri</c>.</summary>
    internal const string HttpClientName = "redb-identity-request-uri";

    public ValidateRequestObjectHandler(
        IOpenIddictApplicationManager applications,
        IClientKeyResolver keyResolver,
        IHttpClientFactory httpClientFactory,
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<ValidateRequestObjectHandler> logger)
    {
        _applications = applications ?? throw new ArgumentNullException(nameof(applications));
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _identityOptions = (identityOptions ?? throw new ArgumentNullException(nameof(identityOptions))).Value;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ValidateRequestObjectHandler>()
            // Must run before anything inspects the request parameters, because until the request
            // object is unpacked the plain parameters are not the real request.
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateRequestParameter.Descriptor.Order - 100)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var requestObject = context.Request.Request;
        var requestUri = context.Request.RequestUri;

        // PAR hands out urn:ietf:params:oauth:request_uri:* and resolves it itself — leave it alone.
        if (!string.IsNullOrEmpty(requestUri) && requestUri.StartsWith(ParRequestUriPrefix, StringComparison.Ordinal))
            return;

        if (string.IsNullOrEmpty(requestObject) && string.IsNullOrEmpty(requestUri))
            return;

        if (!_identityOptions.Features.EnableJar)
        {
            // Same answer the built-in handlers gave before JAR existed.
            context.Reject(
                error: string.IsNullOrEmpty(requestObject) ? Errors.RequestUriNotSupported : Errors.RequestNotSupported,
                description: string.IsNullOrEmpty(requestObject)
                    ? "The 'request_uri' parameter is not supported."
                    : "The 'request' parameter is not supported.");
            return;
        }

        var options = _identityOptions.Jar;

        // request_uri (by reference): fetch the request object over HTTP, then validate it exactly
        // like an inline one. The fetch is SSRF-guarded — the URL came from the client.
        if (string.IsNullOrEmpty(requestObject))
        {
            if (!options.EnableRequestUri)
            {
                context.Reject(
                    error: Errors.RequestUriNotSupported,
                    description: "The 'request_uri' parameter is not supported.");
                return;
            }

            requestObject = await FetchRequestUriAsync(requestUri!, options, context).ConfigureAwait(false);
            if (requestObject is null) return;   // FetchRequestUriAsync already rejected the context
        }

        if (requestObject.Length > options.MaxRequestObjectLength)
        {
            Reject(context, "The request object is too large.");
            return;
        }

        // client_id must be a plain parameter: without it there is no way to know whose keys should
        // verify the signature, and trusting the client_id from inside an unverified JWT is circular.
        var clientId = context.Request.ClientId;
        if (string.IsNullOrEmpty(clientId))
        {
            Reject(context, "The 'client_id' parameter is required when a request object is used.");
            return;
        }

        if (await _applications.FindByClientIdAsync(clientId) is not RedbObject<ApplicationProps> application)
        {
            Reject(context, "The client application is unknown.");
            return;
        }

        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(requestObject))
        {
            Reject(context, "The request object is not a well-formed JWT.");
            return;
        }

        var token = handler.ReadJsonWebToken(requestObject);
        var algorithm = token.Alg;

        // 'none' is refused unconditionally: an unsigned request object drops the exact integrity
        // guarantee JAR exists to provide, so accepting it would be worse than not supporting JAR.
        if (string.IsNullOrEmpty(algorithm) ||
            string.Equals(algorithm, "none", StringComparison.OrdinalIgnoreCase))
        {
            Reject(context, "Unsigned request objects are not accepted.");
            return;
        }

        if (!options.AllowedSigningAlgorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            Reject(context, $"The request object algorithm '{algorithm}' is not supported.");
            return;
        }

        if (!CheckDeclaredAlgorithm(application, algorithm, clientId, options, context, out var rejected) && rejected)
            return;

        var keys = await _keyResolver.GetSigningKeysAsync(application).ConfigureAwait(false);
        if (keys.Count == 0)
        {
            // No keys, nothing to verify against. Failing closed is the point.
            _logger.LogWarning(
                "JAR: client {ClientId} sent a request object but publishes no usable keys.", clientId);
            Reject(context, "The client has no keys registered to verify the request object.");
            return;
        }

        // Issuer is a Uri; the audience of a request object is this server's issuer string.
        // Match the trimming ApplyDiscoveryResponseHandler uses so aud comparison is consistent.
        var issuerString = _identityOptions.Issuer?.ToString().TrimEnd('/');

        var result = await handler.ValidateTokenAsync(requestObject, new TokenValidationParameters
        {
            IssuerSigningKeys = keys,
            ValidateIssuerSigningKey = true,

            // RFC 9101 §4: iss MUST be the client_id, aud MUST be the authorization server.
            ValidIssuer = clientId,
            ValidateIssuer = true,
            ValidAudience = issuerString,
            ValidateAudience = !string.IsNullOrEmpty(issuerString),

            ValidateLifetime = true,
            RequireExpirationTime = options.RequireExpiration,
            ClockSkew = options.ClockSkew,

            ValidAlgorithms = options.AllowedSigningAlgorithms,
        }).ConfigureAwait(false);

        if (!result.IsValid)
        {
            _logger.LogWarning(
                result.Exception,
                "JAR: request object from client {ClientId} failed validation.", clientId);
            Reject(context, "The request object signature or claims could not be validated.");
            return;
        }

        var validated = (JsonWebToken)result.SecurityToken;

        // A request object naming a different client than the outer parameter is either a mix-up
        // or an attempt to have one client's key authorize another client's request.
        if (validated.TryGetPayloadValue<string>(Parameters.ClientId, out var innerClientId) &&
            !string.IsNullOrEmpty(innerClientId) &&
            !string.Equals(innerClientId, clientId, StringComparison.Ordinal))
        {
            Reject(context, "The request object's 'client_id' does not match the request.");
            return;
        }

        MergeParameters(context, validated);

        _logger.LogDebug("JAR: request object accepted for client {ClientId} (alg {Algorithm}).", clientId, algorithm);
    }

    /// <summary>
    /// Fetches the request object referenced by <c>request_uri</c>. Returns the raw JWT, or
    /// <see langword="null"/> after rejecting the context (SSRF-blocked, unreachable, or too large).
    /// </summary>
    private async Task<string?> FetchRequestUriAsync(
        string requestUri, JarOptions options, ValidateAuthorizationRequestContext context)
    {
        var rejection = await OutboundUrlGuard.ValidateAsync(
            requestUri,
            options.RequestUriRequireHttps,
            options.RequestUriAllowPrivateNetworkTargets,
            context.CancellationToken).ConfigureAwait(false);

        if (rejection != OutboundUrlGuard.Rejection.None)
        {
            // Refused before any socket opens: the URL is client-controlled, so an internal target
            // is an SSRF attempt, not a fetch.
            _logger.LogWarning("JAR: refusing to fetch request_uri: {Reason}.", OutboundUrlGuard.Describe(rejection));
            Reject(context, "The request_uri could not be retrieved.");
            return null;
        }

        try
        {
            var http = _httpClientFactory.CreateClient(HttpClientName);
            http.Timeout = options.RequestUriFetchTimeout;
            http.MaxResponseContentBufferSize = options.MaxRequestObjectLength;

            var body = await http.GetStringAsync(requestUri, context.CancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(body))
            {
                Reject(context, "The request_uri returned an empty document.");
                return null;
            }
            return body;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // Unreachable / too large / bad response → fail closed.
            _logger.LogWarning(e, "JAR: failed to fetch request_uri.");
            Reject(context, "The request_uri could not be retrieved.");
            return null;
        }
    }

    /// <summary>
    /// Compares the request object's algorithm against the client's declared
    /// <c>RequestObjectSigningAlg</c>. Returns whether they match; <paramref name="rejected"/>
    /// reports whether the request was rejected (only in <see cref="JarEnforcementMode.Enforce"/>).
    /// </summary>
    private bool CheckDeclaredAlgorithm(
        RedbObject<ApplicationProps> application,
        string algorithm,
        string clientId,
        JarOptions options,
        ValidateAuthorizationRequestContext context,
        out bool rejected)
    {
        rejected = false;

        var declared = application.Props.RequestObjectSigningAlg;
        if (string.IsNullOrWhiteSpace(declared) || options.EnforcementMode == JarEnforcementMode.Off)
            return true;

        if (string.Equals(declared, algorithm, StringComparison.Ordinal)) return true;

        if (options.EnforcementMode == JarEnforcementMode.LogOnly)
        {
            _logger.LogWarning(
                "JAR: client {ClientId} declares request_object_signing_alg '{Declared}' but signed with " +
                "'{Actual}'. Allowed because JarEnforcementMode is LogOnly; it would be rejected under Enforce.",
                clientId, declared, algorithm);
            return false;
        }

        Reject(context, $"The request object must be signed with '{declared}'.");
        rejected = true;
        return false;
    }

    /// <summary>
    /// RFC 9101 §6.1 — parameters inside the request object take precedence, and outside values
    /// that are not repeated inside are ignored. Copying the JWT's claims over the request achieves
    /// both: everything the client meant is present, and anything it did not sign cannot influence
    /// the decision.
    /// </summary>
    private static void MergeParameters(ValidateAuthorizationRequestContext context, JsonWebToken token)
    {
        foreach (var claim in token.Claims)
        {
            // JWT plumbing describes the request object itself, not the authorization request.
            if (claim.Type is "iss" or "aud" or "exp" or "nbf" or "iat" or "jti") continue;

            context.Request.SetParameter(claim.Type, new OpenIddictParameter(claim.Value));
        }

        // The request object has been unpacked into individual parameters; drop it so nothing
        // downstream re-reads or re-validates it (and so the wire request now looks like a plain
        // authorization request, which every later handler already understands).
        context.Request.RemoveParameter(Parameters.Request);
        context.Request.RemoveParameter(Parameters.RequestUri);

        // `context.RedirectUri` is a strongly-typed context property that OpenIddict populates from
        // the request BEFORE this handler runs — so in a JAR flow, where redirect_uri arrived only
        // inside the JWT, it was seeded empty. ValidateRedirectUriParameter reads THAT property
        // (not context.Request.RedirectUri), so without this line it rejects the request as
        // "redirect_uri missing" even though the merged parameter is present. Re-seed it from the
        // now-merged request. (Other validators — response_type, scope, … — read context.Request
        // directly, so only redirect_uri needs this bridge.)
        if (!string.IsNullOrEmpty(context.Request.RedirectUri))
            context.SetRedirectUri(context.Request.RedirectUri);
    }

    /// <summary>
    /// All JAR failures surface as <c>invalid_request_object</c> (RFC 9101 §5) with a description
    /// that says what was wrong but never echoes token content back to the caller.
    /// </summary>
    private static void Reject(ValidateAuthorizationRequestContext context, string description)
        => context.Reject(error: "invalid_request_object", description: description);
}
