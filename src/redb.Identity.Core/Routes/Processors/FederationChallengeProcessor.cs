using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for the Federation Challenge endpoint.
/// Resolves the requested provider, generates an authorization redirect (PKCE + nonce),
/// encrypts state via <see cref="FederationStateProtector"/>, and returns a 302 redirect.
/// </summary>
internal sealed class FederationChallengeProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public FederationChallengeProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var providerId = body?.TryGetValue("provider", out var p) == true ? p?.ToString() : null;
        var returnUrl = body?.TryGetValue("returnUrl", out var r) == true ? r?.ToString() : null;
        var callbackUrl = body?.TryGetValue("callbackUrl", out var cb) == true ? cb?.ToString() : null;

        if (string.IsNullOrEmpty(providerId))
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["error"] = "invalid_request",
                ["error_description"] = "Missing 'provider' parameter."
            };
            return;
        }

        // Find the requested federation provider
        var providers = _sp.GetServices<IFederatedAuthProvider>();
        var provider = providers.FirstOrDefault(p => p.ProviderId == providerId);

        if (provider is null)
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["error"] = "invalid_request",
                ["error_description"] = $"Unknown federation provider '{providerId}'."
            };
            return;
        }

        if (string.IsNullOrEmpty(callbackUrl))
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["error"] = "server_error",
                ["error_description"] = "Callback URL not configured."
            };
            return;
        }

        // Generate challenge (PKCE + nonce + auth URL)
        var challenge = await provider.CreateChallengeAsync(callbackUrl, returnUrl ?? "/", ct)
            .ConfigureAwait(false);

        // C6: optionally mint per-flow browser-binding secret. The HTTP transport
        // converts `federation-binding-secret` into a Secure HttpOnly SameSite=Lax cookie.
        var fedOptions = _sp.GetService<RedbIdentityOptions>()?.FederationState
            ?? new FederationStateOptions();
        string? bindingSecret = null;
        string? bindingHash = null;
        if (fedOptions.RequireBrowserBinding)
        {
            var raw = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(raw);
            bindingSecret = Convert.ToBase64String(raw);
            bindingHash = FederationStateProtector.ComputeBindingHash(bindingSecret);
        }

        // Encrypt state with DataProtection (contains providerId, returnUrl, nonce, codeVerifier, jti, optional bindingHash)
        var stateProtector = _sp.GetRequiredService<FederationStateProtector>();
        var protectedState = stateProtector.Protect(new FederationState
        {
            ProviderId = providerId,
            ReturnUrl = returnUrl,
            Nonce = challenge.Nonce,
            CodeVerifier = challenge.CodeVerifier,
            BindingHash = bindingHash,
        });

        // Replace the provider's opaque state with our encrypted state in the redirect URL
        var redirectUri = challenge.RedirectUri.Replace(
            Uri.EscapeDataString(challenge.State),
            Uri.EscapeDataString(protectedState));

        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["redirect_uri"] = redirectUri
        };
        if (bindingSecret is not null)
        {
            exchange.Properties["federation-binding-secret"] = bindingSecret;
            exchange.Properties["federation-binding-cookie-name"] = fedOptions.BindingCookieName;
        }

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederationChallengeInitiated;
        var timeProvider = _sp.GetService<TimeProvider>() ?? TimeProvider.System;
        exchange.Properties["identity-event-data"] = new
        {
            ProviderId = providerId,
            Timestamp = timeProvider.GetUtcNow()
        };
    }
}
