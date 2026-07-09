using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Contracts.Federation;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H8 (DoD §4 gap (b)/(d)): self-service federated identity management backing
/// <c>/me/federated-identities</c>. Lets a logged-in user list, add (link) or remove
/// (unlink) federated identities tied to their own account. Operations:
/// <list type="bullet">
///   <item><c>list</c> — returns all <see cref="FederatedIdentityProps"/> rows for the
///   caller's user id.</item>
///   <item><c>link-challenge</c> — starts an OIDC dance for an additional provider; the
///   encrypted state carries the caller's user id, so the existing
///   <c>FederationCallbackProcessor</c> performs a link instead of a login.</item>
///   <item><c>unlink</c> — removes a single (provider) link. Refuses when the link is
///   the user's last credential method (no other federated link AND no local password)
///   to prevent the user from locking themselves out (gap (d)).</item>
/// </list>
/// </summary>
internal sealed class MeFederatedIdentitiesProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;

    public MeFederatedIdentitiesProcessor(IRouteContext context, IServiceProvider sp, string? redbName = null)
    {
        _context = context;
        _sp = sp;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var callerId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "invalid_token",
                $"The access token does not carry a numeric subject claim required for self-service APIs (got subject={MeProcessorHelpers.GetRawCallerSubject(exchange) ?? "<null>"}).");
            return;
        }

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        var redb = _context.GetRedbService(_redbName, exchange);

        switch (operation)
        {
            case "list":
                await List(redb, exchange, callerId.Value, ct);
                break;
            case "link-challenge":
                await LinkChallenge(exchange, callerId.Value, ct);
                break;
            case "unlink":
                await Unlink(redb, exchange, callerId.Value, ct);
                break;
            default:
                MeProcessorHelpers.Reject(exchange, 400, "invalid_operation",
                    $"Unknown operation: {operation}");
                break;
        }
    }

    private static async Task List(
        IRedbService redb, IExchange exchange, long userId, CancellationToken ct)
    {
        var links = await redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.Key == userId)
            .OrderBy(o => o.ProviderId)
            .ToListAsync()
            .ConfigureAwait(false);

        var response = links
            .Select(o => new FederatedIdentityResponse
            {
                ProviderId = o.Props.ProviderId,
                ExternalSub = o.Props.ExternalSub,
                ExternalEmail = o.Props.ExternalEmail,
                ExternalDisplayName = o.Props.ExternalDisplayName,
                LinkedAt = o.Props.LinkedAt,
                LastLoginAt = o.Props.LastLoginAt,
            })
            .ToList();

        exchange.Out ??= new Message();
        exchange.Out.Body = response;
    }

    private async Task LinkChallenge(IExchange exchange, long userId, CancellationToken ct)
    {
        // Body shape: contracted DTO from controller, or dict for direct-vm dispatch.
        string? providerId = null;
        string? returnUrl = null;
        string? callbackUrl = null;
        switch (exchange.In.Body)
        {
            case LinkFederatedIdentityRequest req:
                providerId = req.ProviderId;
                returnUrl = req.ReturnUrl;
                break;
            case IDictionary<string, object?> dict:
                providerId = dict.TryGetValue("providerId", out var p) ? p?.ToString() : null;
                returnUrl = dict.TryGetValue("returnUrl", out var r) ? r?.ToString() : null;
                callbackUrl = dict.TryGetValue("callbackUrl", out var cb) ? cb?.ToString() : null;
                break;
        }

        // The callbackUrl is normally injected by the HTTP transport (it knows the public
        // base URL). Direct-vm callers must supply it explicitly in the body dict.
        if (string.IsNullOrWhiteSpace(providerId))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "ProviderId is required");
            return;
        }
        if (string.IsNullOrWhiteSpace(callbackUrl))
        {
            // Fallback: compute from the server's configured Issuer + the standard
            // /connect/federation/callback path. Closes the gap where the HTTP-facing
            // controller resolves IdentityTransportOptions through a Route-context SP
            // that doesn't have the IOptions binding wired and returns the default
            // https://localhost/ (causing mock IdPs to redirect to an unreachable URL).
            // Same shape as the static /connect/federation/callback route registered in
            // HttpFacadeRouteBuilder, so the existing FederationCallbackProcessor handles it.
            // RedbIdentityOptions lives in DI as IOptions<T>, not as the raw type — same
            // gotcha that bit the controller-side resolution.
            var identityOpts = _sp.GetService<Microsoft.Extensions.Options.IOptions<RedbIdentityOptions>>()?.Value;
            var issuer = identityOpts?.Issuer?.AbsoluteUri?.TrimEnd('/');
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                callbackUrl = $"{issuer}/connect/federation/callback";
            }
        }
        if (string.IsNullOrWhiteSpace(callbackUrl))
        {
            MeProcessorHelpers.Reject(exchange, 500, "server_error", "Federation callback URL is not configured.");
            return;
        }

        var providers = _sp.GetServices<IFederatedAuthProvider>();
        var provider = providers.FirstOrDefault(p => string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
        if (provider is null)
        {
            MeProcessorHelpers.Reject(exchange, 400, "invalid_request",
                $"Unknown federation provider '{providerId}'.");
            return;
        }

        var challenge = await provider.CreateChallengeAsync(callbackUrl, returnUrl ?? "/", ct)
            .ConfigureAwait(false);

        // C6 parity with FederationChallengeProcessor: optionally mint per-flow
        // browser-binding secret. The HTTP transport converts the property into a Secure
        // HttpOnly SameSite=Lax cookie that the callback validates.
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

        // Encrypt state with LinkUserId set — the callback will treat this as a link op.
        var stateProtector = _sp.GetRequiredService<FederationStateProtector>();
        var protectedState = stateProtector.Protect(new FederationState
        {
            ProviderId = providerId,
            ReturnUrl = returnUrl,
            Nonce = challenge.Nonce,
            CodeVerifier = challenge.CodeVerifier,
            LinkUserId = userId,
            BindingHash = bindingHash,
        });

        var redirectUri = challenge.RedirectUri.Replace(
            Uri.EscapeDataString(challenge.State),
            Uri.EscapeDataString(protectedState));

        exchange.Out ??= new Message();
        exchange.Out.Body = new LinkFederatedIdentityChallengeResponse { RedirectUri = redirectUri };
        if (bindingSecret is not null)
        {
            exchange.Properties["federation-binding-secret"] = bindingSecret;
            exchange.Properties["federation-binding-cookie-name"] = fedOptions.BindingCookieName;
        }
    }

    private static async Task Unlink(
        IRedbService redb, IExchange exchange, long userId, CancellationToken ct)
    {
        // Body shape: route-supplied dict with "providerId" path segment.
        string? providerId = null;
        switch (exchange.In.Body)
        {
            case IDictionary<string, object?> dict
                when dict.TryGetValue("providerId", out var p):
                providerId = p?.ToString();
                break;
        }

        if (string.IsNullOrWhiteSpace(providerId))
        {
            MeProcessorHelpers.Reject(exchange, 400, "validation_error", "ProviderId is required");
            return;
        }

        // Load the full set of federations to determine whether removing this one would
        // leave the user without any usable credential.
        var allLinks = await redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()
            .ConfigureAwait(false);

        var match = allLinks.FirstOrDefault(o =>
            string.Equals(o.Props.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            MeProcessorHelpers.Reject(exchange, 404, "not_found",
                $"No linked federated identity from provider '{providerId}' for the current user.");
            return;
        }

        // Last-credential guard (gap (d)): if this is the only link AND the user never
        // set their own password, reject with a structured error so the caller can show a
        // helpful message ("set a password first").
        if (allLinks.Count == 1)
        {
            var props = await redb.Query<UserProps>()
                .WhereRedb(o => o.Key == userId)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);

            var hasPassword = props?.Props.HasUserPassword == true;
            if (!hasPassword)
            {
                MeProcessorHelpers.Reject(exchange, 409, "last_credential_method",
                    "This is your last sign-in method. Set a local password before removing this link.");
                return;
            }
        }

        await redb.DeleteAsync(match).ConfigureAwait(false);

        // Mirror to denormalized cache on UserProps.
        var oidcObj = await redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (oidcObj?.Props.ExternalIdentities is { } map && map.Remove(providerId))
            await redb.SaveAsync(oidcObj).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = new { unlinked = true, providerId };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederatedIdentityUnlinked;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            ProviderId = providerId,
            SelfService = true,
        };
    }
}
