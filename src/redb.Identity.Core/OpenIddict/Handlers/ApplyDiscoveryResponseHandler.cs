using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the OpenID Connect discovery document response to <see cref="IExchange.Out"/>.
/// Maps to the <c>.well-known/openid-configuration</c> endpoint.
/// </summary>
internal sealed class ApplyDiscoveryResponseHandler
    : IOpenIddictServerHandler<ApplyConfigurationResponseContext>
{
    private readonly RedbIdentityOptions _identityOptions;

    public ApplyDiscoveryResponseHandler(IOptions<RedbIdentityOptions> identityOptions)
    {
        _identityOptions = identityOptions.Value;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<ApplyDiscoveryResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyConfigurationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        // Add end_session_endpoint (logout is handled by LogoutProcessor, not OpenIddict pipeline)
        if (context.Options?.Issuer is not null)
        {
            var issuer = context.Options.Issuer.ToString().TrimEnd('/');
            context.Response["end_session_endpoint"] = $"{issuer}/connect/logout";

            // RFC 9126 §5 — advertise the PAR endpoint URL so clients can locate it without
            // hard-coding the path. OpenIddict's built-in discovery handler does NOT emit
            // `pushed_authorization_request_endpoint` even when PAR is wired (it surfaces
            // only the auth-methods list), so we add the URL here. The companion
            // `require_pushed_authorization_requests` flag is emitted only when the global
            // enforcement is on; per-client enforcement is not advertised globally because
            // it's a property of individual client registrations, not the AS.
            if (_identityOptions.Features.EnablePushedAuthorization)
            {
                context.Response["pushed_authorization_request_endpoint"] = $"{issuer}/connect/par";
                if (_identityOptions.RequirePushedAuthorizationRequests)
                    context.Response["require_pushed_authorization_requests"] = true;
            }
        }

        // OIDC Back-Channel Logout: we support RP-Initiated Logout via end_session_endpoint.
        // frontchannel_logout is NOT advertised — no iframe-based logout endpoint is implemented.
        // Per OIDC Back-Channel Logout 1.0 §3, advertise backchannel_logout_supported when
        // BackchannelLogoutDispatcher is wired (which it always is from C8 onwards). The
        // session-id ('sid') claim is included only when the RP opts in via
        // backchannel_logout_session_required on its client metadata, so we advertise the
        // session_supported flag accordingly.
        context.Response["backchannel_logout_supported"] = true;
        context.Response["backchannel_logout_session_supported"] = true;

        // D1: per RFC 8414 §2 these auth-methods fields are recommended (and several
        // conformance suites flag them as missing). OpenIddict already exposes
        // token_endpoint_auth_methods_supported; mirror it on revocation/introspection
        // (we accept the same client_secret_basic/post + none methods on all three).
        var tokenAuthMethods = context.Response["token_endpoint_auth_methods_supported"];
        if (tokenAuthMethods is { } existingMethods && existingMethods.Value is not null)
        {
            context.Response["revocation_endpoint_auth_methods_supported"] = existingMethods;
            context.Response["introspection_endpoint_auth_methods_supported"] = existingMethods;
        }

        // RFC 8414 §2 / RFC 7591 §2 — when the server supports `private_key_jwt`
        // (or `client_secret_jwt`) it SHOULD advertise the JWS signing algorithms
        // it accepts on the JWT-bearer client assertion. OpenIddict 6 validates
        // assertions using its built-in IdentityModel-backed pipeline, which covers
        // RSA / ECDSA / RSA-PSS at standard hash widths. The same list applies to
        // /introspect and /revoke since those endpoints share the auth pipeline.
        var clientAssertionAlgs = JsonSerializer.Deserialize<JsonElement>(
            "[\"RS256\",\"RS384\",\"RS512\",\"PS256\",\"PS384\",\"PS512\",\"ES256\",\"ES384\",\"ES512\"]");
        context.Response.RemoveParameter("token_endpoint_auth_signing_alg_values_supported");
        context.Response["token_endpoint_auth_signing_alg_values_supported"] = clientAssertionAlgs;
        context.Response.RemoveParameter("introspection_endpoint_auth_signing_alg_values_supported");
        context.Response["introspection_endpoint_auth_signing_alg_values_supported"] = clientAssertionAlgs;
        context.Response.RemoveParameter("revocation_endpoint_auth_signing_alg_values_supported");
        context.Response["revocation_endpoint_auth_signing_alg_values_supported"] = clientAssertionAlgs;

        // Z4 (RFC 9449 §5.1): advertise DPoP support and the supported signing algorithms.
        // OpenIddict's built-in discovery handler emits its own short list during the Handle
        // phase ([ES256, ES384, PS256, RS256]); when we set our (typically wider) list here
        // via the indexer, OpenIddictParameter merges array-typed parameters instead of
        // replacing them — producing a duplicated list. RemoveParameter() forces a clean
        // overwrite so discovery shows exactly the configured algorithms.
        if (_identityOptions.Dpop.Enabled && _identityOptions.Dpop.AllowedSigningAlgorithms.Length > 0)
        {
            context.Response.RemoveParameter("dpop_signing_alg_values_supported");
            context.Response["dpop_signing_alg_values_supported"] =
                JsonSerializer.Deserialize<JsonElement>(
                    JsonSerializer.Serialize(_identityOptions.Dpop.AllowedSigningAlgorithms));
        }

        // Federation providers (non-standard extension). Skip placeholder entries
        // (ClientId / Authority = REPLACE_ME) so discovery stays consistent with
        // the public-providers list endpoint: an operator should never see a
        // provider id in /.well-known/openid-configuration that the login page
        // refuses to render. The DI registration applies the same filter, so
        // FederationChallengeProcessor returns "Unknown federation provider"
        // for placeholder ids anyway — surfacing them in discovery would be a
        // dead pointer.
        if (_identityOptions.Features.EnableFederation && _identityOptions.FederationProviders.Count > 0)
        {
            static bool IsPlaceholder(string? v)
                => string.IsNullOrWhiteSpace(v)
                   || v.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase);

            var issuerBase = context.Options?.Issuer?.ToString().TrimEnd('/');
            var providerList = _identityOptions.FederationProviders
                .Where(p => !IsPlaceholder(p.ClientId) && !IsPlaceholder(p.Authority))
                .Select(p => new
                {
                    id = p.ProviderId,
                    display_name = p.DisplayName,
                    authorization_endpoint = $"{issuerBase}/federation/{p.ProviderId}/login"
                })
                .ToList();
            if (providerList.Count > 0)
            {
                context.Response["federation_providers"] = JsonSerializer.Deserialize<JsonElement>(
                    JsonSerializer.Serialize(providerList));
            }
        }

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);

        // OpenIddict's default discovery handler appends its own short DPoP-alg list
        // ([ES256, ES384, PS256, RS256]) AFTER our handler runs, even when we call
        // RemoveParameter — the merge happens later in the pipeline. Dedupe here, in
        // the already-materialised Out.Body, so the wire-shape is canonical.
        if (exchange.Out?.Body is Dictionary<string, object?> body)
        {
            DedupeStringArray(body, "dpop_signing_alg_values_supported");
            DedupeStringArray(body, "id_token_signing_alg_values_supported");
            DedupeStringArray(body, "code_challenge_methods_supported");
            DedupeStringArray(body, "token_endpoint_auth_methods_supported");
            DedupeStringArray(body, "introspection_endpoint_auth_methods_supported");
            DedupeStringArray(body, "revocation_endpoint_auth_methods_supported");
            DedupeStringArray(body, "device_authorization_endpoint_auth_methods_supported");
            DedupeStringArray(body, "pushed_authorization_request_endpoint_auth_methods_supported");
            DedupeStringArray(body, "grant_types_supported");
            DedupeStringArray(body, "response_types_supported");
            DedupeStringArray(body, "response_modes_supported");
            DedupeStringArray(body, "scopes_supported");
            DedupeStringArray(body, "claims_supported");
            DedupeStringArray(body, "subject_types_supported");
            DedupeStringArray(body, "prompt_values_supported");
        }

        context.HandleRequest();
        return default;
    }

    private static void DedupeStringArray(Dictionary<string, object?> body, string key)
    {
        if (!body.TryGetValue(key, out var raw) || raw is not List<object?> list || list.Count == 0)
            return;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var deduped = new List<object?>(list.Count);
        foreach (var item in list)
        {
            var s = item?.ToString();
            if (s is null) continue;
            if (seen.Add(s)) deduped.Add(item);
        }
        if (deduped.Count != list.Count)
            body[key] = deduped;
    }
}
