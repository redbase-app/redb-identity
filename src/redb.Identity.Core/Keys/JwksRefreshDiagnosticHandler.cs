using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Validation;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace redb.Identity.Core.Keys;

/// <summary>
/// **Batch 12 diagnostic.** Fires on every rejected validation. Logs the key picture from
/// both the server options and the validation options so we can see *which* layer hangs
/// onto a stale snapshot after a JWKS rotate. Wired in the validation pipeline with
/// max-priority order so it runs after the built-in rejection.
/// </summary>
internal sealed class JwksRefreshDiagnosticHandler
    : IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
        = OpenIddictValidationHandlerDescriptor
            .CreateBuilder<ProcessAuthenticationContext>()
            .UseSingletonHandler<JwksRefreshDiagnosticHandler>()
            .SetOrder(int.MaxValue - 500)
            .Build();

    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly IOptionsMonitor<OpenIddictValidationOptions> _validationOptions;
    private readonly ILogger<JwksRefreshDiagnosticHandler> _logger;

    public JwksRefreshDiagnosticHandler(
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        IOptionsMonitor<OpenIddictValidationOptions> validationOptions,
        ILogger<JwksRefreshDiagnosticHandler> logger)
    {
        _serverOptions = serverOptions;
        _validationOptions = validationOptions;
        _logger = logger;
    }

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        if (!context.IsRejected) return default;

        try
        {
            string? tokenKid = null;
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                var parts = context.AccessToken.Split('.');
                if (parts.Length >= 2)
                {
                    try
                    {
                        var s = parts[0].Replace('-','+').Replace('_','/');
                        var pad = s.Length % 4;
                        s += pad == 2 ? "==" : pad == 3 ? "=" : "";
                        var hdrJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
                        using var doc = System.Text.Json.JsonDocument.Parse(hdrJson);
                        if (doc.RootElement.TryGetProperty("kid", out var kidEl))
                            tokenKid = kidEl.GetString();
                    }
                    catch { /* may be encrypted JWE */ }
                }
            }

            var srv = _serverOptions.CurrentValue;
            var val = _validationOptions.CurrentValue;

            var serverKids = srv.SigningCredentials.Select(c => c.Key?.KeyId ?? "(no-kid)").ToList();
            var serverEncKids = srv.EncryptionCredentials.Select(c => c.Key?.KeyId ?? "(no-kid)").ToList();
            var valIssuerKids = val.TokenValidationParameters?.IssuerSigningKeys?
                .Select(k => k.KeyId ?? "(no-kid)").ToList() ?? new List<string>();
            var valDecryptKids = val.TokenValidationParameters?.TokenDecryptionKeys?
                .Select(k => k.KeyId ?? "(no-kid)").ToList() ?? new List<string>();
            var serverNotInVal = serverKids.Except(valIssuerKids).ToList();

            _logger.LogWarning(
                "JWKS-DIAG validation REJECTED. err={Err} desc={Desc} | token.kid={TokenKid} | " +
                "server.signing=[{ServerKids}] (n={SrvN}) | server.encryption=[{ServerEncKids}] | " +
                "val.issuerSigning=[{ValKids}] (n={ValN}) | val.decrypt=[{ValDecKids}] | " +
                "server_not_in_val=[{Delta}]",
                context.Error, context.ErrorDescription,
                tokenKid ?? "(none/JWE)",
                string.Join(",", serverKids), serverKids.Count,
                string.Join(",", serverEncKids),
                string.Join(",", valIssuerKids), valIssuerKids.Count,
                string.Join(",", valDecryptKids),
                string.Join(",", serverNotInVal));
        }
        catch { /* diagnostic — never throw */ }

        return default;
    }
}
