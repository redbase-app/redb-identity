using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Keys;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// JWKS endpoint that reads keys live from <see cref="ISigningKeyStore"/> on every request,
/// bypassing the static <c>OpenIddictServerOptions.SigningCredentials</c> list (which is
/// frozen at process start). Wired in place of the default <c>JwksEndpointProcessor</c>
/// when <see cref="Configuration.RedbIdentityOptions.UsePropsSigningKeyStore"/> is enabled,
/// so admin <c>/signing-keys/rotate</c> and <c>/signing-keys/{kid}/retire</c> reflect on
/// the JWKS immediately without any process restart.
/// <para>
/// Caveat: OpenIddict still picks the signing credential for NEW tokens from its frozen
/// options list. RPs cache the live JWKS (Cache-Control: max-age=3600) and will validate
/// in-flight tokens against whichever kid is present. New-token-kid follows new-key only
/// after the OpenIddict cache refreshes (process restart or future IOptionsMonitor wiring).
/// </para>
/// </summary>
internal sealed class LiveJwksProcessor : IProcessor
{
    private readonly ISigningKeyStore _store;

    public LiveJwksProcessor(ISigningKeyStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var keys = await _store.GetAllAsync(ct).ConfigureAwait(false);

        // Convert each stored SecurityKey to its public JWK form (no private material).
        // Filter to signing-kind only; encryption keys live in a separate part of the spec
        // (`use=enc`) and we currently advertise sign-only on this endpoint.
        var jwks = new List<object>(keys.Length);
        foreach (var m in keys)
        {
            if (!string.Equals(m.KeyKind, "signing", StringComparison.OrdinalIgnoreCase))
                continue;
            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(m.SecurityKey);
            // ConvertFromSecurityKey copies the private components for RSA keys; strip them
            // before serialising so the public JWKS doesn't leak `d`, `p`, `q`, `dp`, `dq`, `qi`.
            jwk.D = null;
            jwk.P = null;
            jwk.Q = null;
            jwk.DP = null;
            jwk.DQ = null;
            jwk.QI = null;
            jwk.K = null;
            jwk.Kid = m.Kid;
            jwk.Use = "sig";
            jwk.Alg = m.Algorithm;
            jwks.Add(new
            {
                kty = jwk.Kty,
                use = jwk.Use,
                alg = jwk.Alg,
                kid = jwk.Kid,
                n = jwk.N,
                e = jwk.E,
            });
        }

        var body = JsonSerializer.SerializeToUtf8Bytes(new { keys = jwks });
        var msg = new Message(body)
        {
            ContentType = "application/json",
        };
        msg.Headers["redbHttp.ResponseCode"] = 200;
        msg.Headers["redbHttp.ResponseContentType"] = "application/json";
        // D2: 1-hour cache matches Microsoft / Google / Auth0 conventions and is well
        // within the typical 24-72h rotation grace window. With the live store, RPs that
        // miss-cache after rotation see the new kid on the next refresh; in-flight tokens
        // still validate as long as their kid is in the store's NotAfter window.
        msg.Headers["Cache-Control"] = "public, max-age=3600";
        msg.Headers["Vary"] = "Accept";

        exchange.Out = msg;
    }
}
