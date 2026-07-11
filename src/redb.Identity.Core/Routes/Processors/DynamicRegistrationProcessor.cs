using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Registration;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Serialization;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// RFC 7591 Dynamic Client Registration endpoint processor.
/// Accepts a JSON registration request and creates a new OAuth application.
/// </summary>
internal sealed class DynamicRegistrationProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly RedbIdentityOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger? _logger;

    // Default grant types per RFC 7591 §2
    private static readonly string[] DefaultGrantTypes = ["authorization_code"];
    private static readonly string[] DefaultResponseTypes = ["code"];

    public DynamicRegistrationProcessor(
        IRouteContext context,
        IOptions<RedbIdentityOptions> options,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null)
    {
        _context = context;
        _options = options.Value;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = loggerFactory?.CreateLogger("DynamicRegistrationProcessor");
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var swTotal = Stopwatch.StartNew();
        // Validate initial access token if configured (RFC 7591 §1.2)
        if (_options.DynamicRegistrationInitialAccessToken is { } expectedToken)
        {
            // access_token header is set by ExtractBearerToken (already stripped "Bearer " prefix)
            var tokenValue = exchange.In.GetHeader<string>("access_token");
            if (tokenValue is null)
            {
                // Fallback: check raw Authorization header (direct-vm tests, non-HTTP transports)
                var authHeader = exchange.In.GetHeader<string>("Authorization");
                if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
                    tokenValue = authHeader[7..];
            }

            if (tokenValue is null ||
                !CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(tokenValue),
                    System.Text.Encoding.UTF8.GetBytes(expectedToken)))
            {
                SetError(exchange, "invalid_token", "A valid initial access token is required", 401);
                return;
            }
        }

        // Deserialize the request body
        DynamicRegistrationRequest? request;
        try
        {
            request = exchange.In.Body switch
            {
                DynamicRegistrationRequest typed => typed,
                byte[] bytes => JsonSerializer.Deserialize<DynamicRegistrationRequest>(bytes),
                string json => JsonSerializer.Deserialize<DynamicRegistrationRequest>(json),
                _ => null
            };
        }
        catch (JsonException)
        {
            request = null;
        }

        if (request is null)
        {
            SetError(exchange, "invalid_client_metadata", "Invalid or missing request body");
            return;
        }

        // Resolve grant types (RFC 7591 §2: default = authorization_code)
        var grantTypes = request.GrantTypes is { Length: > 0 }
            ? request.GrantTypes
            : DefaultGrantTypes;

        // Validate grant types against policy
        var disallowed = grantTypes.Except(_options.DynamicRegistrationAllowedGrantTypes).ToArray();
        if (disallowed.Length > 0)
        {
            SetError(exchange, "invalid_client_metadata",
                $"Grant type(s) not allowed: {string.Join(", ", disallowed)}");
            return;
        }

        // Resolve response types (RFC 7591 §2: default = code)
        var responseTypes = request.ResponseTypes is { Length: > 0 }
            ? request.ResponseTypes
            : DefaultResponseTypes;

        // Validate scopes against policy
        var requestedScopes = ParseScopes(request.Scope);
        var disallowedScopes = requestedScopes.Except(_options.DynamicRegistrationAllowedScopes).ToArray();
        if (disallowedScopes.Length > 0)
        {
            SetError(exchange, "invalid_client_metadata",
                $"Scope(s) not allowed: {string.Join(", ", disallowedScopes)}");
            return;
        }

        // Validate redirect URIs (required for authorization_code / implicit)
        if (grantTypes.Contains("authorization_code") || grantTypes.Contains("implicit"))
        {
            if (request.RedirectUris is not { Length: > 0 })
            {
                SetError(exchange, "invalid_redirect_uri",
                    "redirect_uris is required for authorization_code / implicit grant types");
                return;
            }

            var uriErr = IdentityProcessorHelpers.ValidateUris(request.RedirectUris, "redirect URI");
            if (uriErr is not null)
            {
                SetError(exchange, "invalid_redirect_uri", uriErr);
                return;
            }
        }

        if (request.PostLogoutRedirectUris is { Length: > 0 })
        {
            var uriErr = IdentityProcessorHelpers.ValidateUris(request.PostLogoutRedirectUris, "post-logout redirect URI");
            if (uriErr is not null)
            {
                SetError(exchange, "invalid_client_metadata", uriErr);
                return;
            }
        }

        // Determine client type from token_endpoint_auth_method (RFC 7591 §2)
        var authMethod = request.TokenEndpointAuthMethod ?? "client_secret_basic";
        string clientType;
        string? plainSecret = null;
        string? jwksJson = null;

        if (authMethod == "none")
        {
            clientType = "public";
        }
        else if (authMethod is "client_secret_basic" or "client_secret_post")
        {
            clientType = "confidential";
            plainSecret = GenerateClientSecret();
        }
        else if (authMethod == "private_key_jwt")
        {
            // RFC 7521 §6.2 / RFC 7523 §2.2 — clients authenticating with a JWT bearer
            // assertion are confidential clients (they hold a private signing key) but
            // do NOT carry a server-issued client_secret.
            clientType = "confidential";

            // RFC 7591 §2 requires `jwks` OR `jwks_uri` for private_key_jwt; we currently
            // only support the inline `jwks` shape (jwks_uri would need an HTTP fetch +
            // periodic refresh, deferred to a follow-up). The JWKS is stored verbatim and
            // consulted by OpenIddict when validating the JWT-bearer client assertion
            // signature (IOpenIddictApplicationStore.GetJsonWebKeySetAsync).
            if (request.JsonWebKeySet is null)
            {
                SetError(exchange, "invalid_client_metadata",
                    "private_key_jwt requires `jwks` (inline JSON Web Key Set with the client's public keys).");
                return;
            }
            try
            {
                var raw = request.JsonWebKeySet.Value.GetRawText();
                // Sanity: must parse as a JWKS with a `keys` array.
                var probe = Microsoft.IdentityModel.Tokens.JsonWebKeySet.Create(raw);
                if (probe.Keys.Count == 0)
                {
                    SetError(exchange, "invalid_client_metadata",
                        "`jwks` must contain at least one public key in `keys`.");
                    return;
                }
                jwksJson = raw;
            }
            catch (Exception ex)
            {
                SetError(exchange, "invalid_client_metadata",
                    $"`jwks` is not a valid JSON Web Key Set: {ex.Message}");
                return;
            }
        }
        else
        {
            SetError(exchange, "invalid_client_metadata",
                $"Unsupported token_endpoint_auth_method: {authMethod}");
            return;
        }

        // Application type (RFC 7591 §2: default = web)
        var applicationType = request.ApplicationType ?? "web";
        if (applicationType is not ("web" or "native"))
        {
            SetError(exchange, "invalid_client_metadata",
                "application_type must be 'web' or 'native'");
            return;
        }

        // Build permissions array (OpenIddict format)
        var permissions = BuildPermissions(grantTypes, responseTypes, requestedScopes);

        // Build requirements. Force PKCE per-client ONLY when the server mandates it
        // (RedbIdentityOptions.RequirePkce, default true = OAuth 2.1 hardening). When PKCE is
        // optional (RequirePkce=false), authorization_code clients register WITHOUT the ft:pkce
        // requirement — they may still use PKCE, but it is not mandated — so the per-client policy
        // matches the server policy (e.g. lets the OpenID Basic OP non-PKCE tests register a client).
        var requirements = new List<string>();
        if (_options.RequirePkce && grantTypes.Contains("authorization_code"))
            requirements.Add("ft:pkce");

        // Generate unique client_id
        var clientId = Guid.NewGuid().ToString("D");

        // Use OpenIddict ApplicationManager to create the client.
        // This ensures the secret is hashed using OpenIddict's built-in mechanism (BCrypt),
        // which is consistent with how ValidateClientSecretAsync verifies credentials.
        var manager = _context.GetIdentityService<IOpenIddictApplicationManager>(exchange);

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = plainSecret,
            ClientType = clientType,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = request.ClientName ?? clientId,
        };

        if (applicationType == "native")
            descriptor.ApplicationType = OpenIddictConstants.ApplicationTypes.Native;

        // RFC 7523 §3 — surface the inline JWKS on the descriptor so PopulateAsync
        // routes it through IOpenIddictApplicationStore.SetJsonWebKeySetAsync (which
        // persists into ApplicationProps.JsonWebKeySet). OpenIddict's built-in
        // private_key_jwt validator on /connect/token et al. then resolves the keys
        // via GetJsonWebKeySetAsync at validation time.
        if (jwksJson is not null)
            descriptor.JsonWebKeySet = Microsoft.IdentityModel.Tokens.JsonWebKeySet.Create(jwksJson);

        if (request.RedirectUris is { Length: > 0 })
            foreach (var uri in request.RedirectUris)
                descriptor.RedirectUris.Add(new Uri(uri));

        if (request.PostLogoutRedirectUris is { Length: > 0 })
            foreach (var uri in request.PostLogoutRedirectUris)
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));

        // OIDC Back-Channel Logout 1.0 §2.2 — store as custom properties so
        // BackchannelLogoutDispatcher can read them at logout time.
        if (!string.IsNullOrWhiteSpace(request.BackchannelLogoutUri))
        {
            descriptor.Properties["backchannel_logout_uri"] =
                JsonDocument.Parse(JsonSerializer.Serialize(request.BackchannelLogoutUri)).RootElement.Clone();
            descriptor.Properties["backchannel_logout_session_required"] =
                JsonDocument.Parse((request.BackchannelLogoutSessionRequired ?? true) ? "true" : "false").RootElement.Clone();
        }

        foreach (var p in permissions)
            descriptor.Permissions.Add(p);

        foreach (var r in requirements)
            descriptor.Requirements.Add(r);

        // Z2 (RFC 7592 §3): generate the registration_access_token and persist its hash
        // so that GET/PUT/DELETE /connect/register/{client_id} can authenticate the caller.
        // The plaintext RAT is returned ONCE in the registration response; after that, only
        // the SHA-256 hex hash lives in PROPS (defense-in-depth against DB dumps).
        var registrationAccessToken = GenerateUrlSafeToken(32);
        var ratHash = ComputeSha256Hex(registrationAccessToken);

        // Split the manager.CreateAsync(descriptor) pipeline manually so the RAT hash
        // is written in the SAME redb roundtrip as the rest of the application:
        //   instantiate → PopulateAsync (without secret) → mutate Props → CreateAsync(app, secret).
        // Pull the plaintext secret out of the descriptor BEFORE Populate, otherwise
        // PopulateAsync stamps the plaintext into Props.ClientSecret and the 2-arg
        // CreateAsync(app, ct) overload's "hash already set" guard rejects it.
        var localSecret = descriptor.ClientSecret;
        descriptor.ClientSecret = null;

        var swPopulate = Stopwatch.StartNew();
        var app = new RedbObject<ApplicationProps> { Props = new ApplicationProps() };
        await manager.PopulateAsync(app, descriptor, ct).ConfigureAwait(false);
        swPopulate.Stop();
        app.Props.RegistrationAccessTokenHash = ratHash;

        // OIDC Back-Channel Logout 1.0 §2.2 — PopulateAsync ignores descriptor.Properties[]
        // (those are OpenIddict's per-store custom-properties bag, not redb Props), so the
        // strongly-typed Props field has to be written manually after Populate.
        if (!string.IsNullOrWhiteSpace(request.BackchannelLogoutUri))
        {
            app.Props.BackchannelLogoutUri = request.BackchannelLogoutUri;
            app.Props.BackchannelLogoutSessionRequired = request.BackchannelLogoutSessionRequired ?? true;
        }

        // RFC 9126 §5 — per-client PAR enforcement. Stored on Props directly so
        // ValidateAuthorizeRequestHandler can read it without lifting the OpenIddict
        // descriptor.Properties bag into Props.
        if (request.RequirePushedAuthorizationRequests == true)
            app.Props.RequirePushedAuthorizationRequests = true;

        // N-4 (Session C/E) — per-client landing-URL whitelists for the password-recovery,
        // verify-email, and change-email flows. Without these the flows are disabled even
        // when the server-side feature toggle is on; persisting them on Props at DCR time
        // is the only way a self-registered client can opt in (admin Update is the other path).
        if (request.PasswordResetUris is { Length: > 0 })
            app.Props.PasswordResetUris = request.PasswordResetUris;
        if (request.EmailVerifyUris is { Length: > 0 })
            app.Props.EmailVerifyUris = request.EmailVerifyUris;
        if (request.ChangeEmailUris is { Length: > 0 })
            app.Props.ChangeEmailUris = request.ChangeEmailUris;

        var swCreate = Stopwatch.StartNew();
        if (localSecret is not null)
            await manager.CreateAsync(app, localSecret, ct).ConfigureAwait(false);
        else
            await manager.CreateAsync(app, ct).ConfigureAwait(false);
        swCreate.Stop();

        _logger?.LogDebug(
            "DCR_TIMING populate={PopulateMs}ms create={CreateMs}ms total={TotalMs}ms hasSecret={HasSecret} grants=[{Grants}] scopes=[{Scopes}] redirectUris={UriCount}",
            swPopulate.ElapsedMilliseconds,
            swCreate.ElapsedMilliseconds,
            swTotal.ElapsedMilliseconds,
            localSecret is not null,
            string.Join(",", grantTypes),
            string.Join(",", requestedScopes),
            request.RedirectUris?.Length ?? 0);

        // Build registration_client_uri from the configured issuer.
        var registrationClientUri = BuildRegistrationClientUri(clientId);

        // Build response (RFC 7591 §3.2.1)
        var now = _timeProvider.GetUtcNow();
        var response = new DynamicRegistrationResponse
        {
            ClientId = clientId,
            ClientSecret = plainSecret,
            ClientSecretExpiresAt = plainSecret is not null ? 0 : null, // 0 = never expires
            ClientIdIssuedAt = now.ToUnixTimeSeconds(),
            RedirectUris = request.RedirectUris,
            TokenEndpointAuthMethod = authMethod,
            GrantTypes = grantTypes,
            ResponseTypes = responseTypes,
            ClientName = request.ClientName,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            Scope = requestedScopes.Length > 0 ? string.Join(' ', requestedScopes) : request.Scope,
            Contacts = request.Contacts,
            SoftwareId = request.SoftwareId,
            SoftwareVersion = request.SoftwareVersion,
            ApplicationType = applicationType,
            PostLogoutRedirectUris = request.PostLogoutRedirectUris,
            JsonWebKeySet = request.JsonWebKeySet,
            JsonWebKeySetUri = request.JsonWebKeySetUri,
            RegistrationAccessToken = registrationAccessToken,
            RegistrationClientUri = registrationClientUri,
            RequirePushedAuthorizationRequests = request.RequirePushedAuthorizationRequests,
            PasswordResetUris = app.Props.PasswordResetUris,
            EmailVerifyUris = app.Props.EmailVerifyUris,
            ChangeEmailUris = app.Props.ChangeEmailUris
        };

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = SerializeResponse(response);
        exchange.Out.Headers["redbHttp.ResponseCode"] = 201;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientRegistered;
        exchange.Properties["identity-event-data"] = new { ClientId = clientId, Source = "dynamic_registration" };
    }

    // ── Helpers ──

    private static string[] ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
            return [];
        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static List<string> BuildPermissions(string[] grantTypes, string[] responseTypes, string[] scopes)
    {
        var perms = new List<string>();

        // Endpoint permissions. We always grant token + introspection + revocation so that
        // dynamically-registered clients can manage their own tokens (RFC 7662 / RFC 7009);
        // OpenIddict refuses these endpoints without explicit permission, which would
        // otherwise return 'unauthorized_client' for the very first introspect call.
        perms.Add("ept:token");
        perms.Add("ept:introspection");
        perms.Add("ept:revocation");
        if (grantTypes.Contains("authorization_code") || grantTypes.Contains("implicit"))
        {
            perms.Add("ept:authorization");
            if (grantTypes.Contains("authorization_code"))
                perms.Add("ept:pushed_authorization"); // RFC 9126 PAR endpoint
        }
        if (grantTypes.Contains("refresh_token"))
            perms.Add("ept:token"); // already added, dedup below
        if (grantTypes.Contains("urn:ietf:params:oauth:grant-type:device_code"))
            perms.Add("ept:device_authorization");

        // Grant type permissions
        foreach (var gt in grantTypes)
            perms.Add($"gt:{gt}");

        // Response type permissions
        foreach (var rt in responseTypes)
            perms.Add($"rst:{rt}");

        // Scope permissions
        foreach (var s in scopes)
            perms.Add($"scp:{s}");

        return perms.Distinct().ToList();
    }

    private static string GenerateClientSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=');
    }

    /// <summary>
    /// Z2: generates a URL-safe registration_access_token using <see cref="RandomNumberGenerator"/>.
    /// Uses base64url without padding so the value can travel in an <c>Authorization: Bearer</c> header.
    /// </summary>
    internal static string GenerateUrlSafeToken(int entropyBytes)
    {
        Span<byte> buf = stackalloc byte[Math.Max(entropyBytes, 16)];
        RandomNumberGenerator.Fill(buf);
        return Convert.ToBase64String(buf)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>SHA-256 hex (lowercase) of the provided plaintext. Used for RAT verification.</summary>
    internal static string ComputeSha256Hex(string plaintext)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(plaintext));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private string BuildRegistrationClientUri(string clientId)
    {
        // Issuer is guaranteed non-null by RedbIdentityOptions validation.
        var issuer = _options.Issuer.AbsoluteUri.TrimEnd('/');
        return $"{issuer}/connect/register/{Uri.EscapeDataString(clientId)}";
    }

    private static IDictionary<string, object?> SerializeResponse(DynamicRegistrationResponse response)
    {
        // RFC 7591 §3.2 — DCR response uses snake_case names defined by the spec
        // (redirect_uris, grant_types, client_id_issued_at, …). Apply the locked OAuth
        // profile via SerializeToElement so the resulting Dictionary already carries the
        // canonical names; transport facades serialise the typed payload themselves.
        // We deliberately avoid SerializeToUtf8Bytes / Serialize<T>->string here: those
        // are wire-encoding APIs and would tie core to a single transport format.
        var element = JsonSerializer.SerializeToElement(response, IdentityCodecProfiles.OAuthOptions);
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var prop in element.EnumerateObject())
            dict[prop.Name] = prop.Value.Clone();
        return dict;
    }

    private static void SetError(IExchange exchange, string error, string description, int statusCode = 400)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        };
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
    }
}
