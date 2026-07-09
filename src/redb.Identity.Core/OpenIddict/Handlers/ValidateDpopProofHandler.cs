using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z4 (RFC 9449): validates the <c>DPoP</c> header on the token endpoint.
/// On success, stores the JWK thumbprint (<c>jkt</c>) in
/// <c>context.Transaction.Properties["dpop:jkt"]</c> so that downstream
/// <see cref="AttachDpopConfirmationClaimHandler"/> can bind it into the issued access token.
/// <para>
/// Soft-mode (the default): if no header is present, the request is allowed through
/// untouched (issuing a Bearer token). Strict-mode (<see cref="DpopOptions.RequireForAccessTokens"/> = true):
/// missing header rejects with <c>invalid_dpop_proof</c>.
/// </para>
/// </summary>
internal sealed class ValidateDpopProofHandler
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private readonly DpopProofValidator _validator;
    private readonly IDpopNonceProvider _nonceProvider;
    private readonly DpopOptions _options;
    private readonly IServiceProvider _sp;
    private readonly ILogger<ValidateDpopProofHandler> _logger;

    public ValidateDpopProofHandler(
        DpopProofValidator validator,
        IDpopNonceProvider nonceProvider,
        IOptions<RedbIdentityOptions> identityOptions,
        IServiceProvider sp,
        ILogger<ValidateDpopProofHandler> logger)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _nonceProvider = nonceProvider ?? throw new ArgumentNullException(nameof(nonceProvider));
        _options = (identityOptions ?? throw new ArgumentNullException(nameof(identityOptions))).Value.Dpop;
        _sp = sp ?? throw new ArgumentNullException(nameof(sp));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// A.8: look up the per-client DPoP-required flag. The handler short-circuits
    /// to "false" on any failure path so a redb hiccup never turns soft-mode into
    /// strict-mode by accident — same defensive posture as
    /// AttachAdditionalIdTokenAudiences and AttachClaimMapperClaims.
    /// </summary>
    private async ValueTask<bool> IsDpopRequiredForClientAsync(string? clientId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(clientId)) return false;
        var redb = _sp.GetService<IRedbService>();
        if (redb is null) return false;

        try
        {
            var app = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == clientId)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            return app?.Hydrate().Props.RequireDpop ?? false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "DPoP: failed to resolve application by client_id '{ClientId}'; treating as not-required", clientId);
            return false;
        }
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<ValidateDpopProofHandler>()
            // Run before HandleTokenRequestHandler — after standard validators.
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        if (!_options.Enabled)
            return;

        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return;

        if (!exchange.In.Headers.TryGetValue("DPoP", out var rawProof) || rawProof is not string proof || string.IsNullOrEmpty(proof))
        {
            // A.8: per-client opt-in is OR'd with the server-wide flag — either
            // path triggers strict-mode rejection on missing header.
            var perClientRequired = await IsDpopRequiredForClientAsync(context.ClientId, context.CancellationToken);
            if (_options.RequireForAccessTokens || perClientRequired)
            {
                IssueNonceHeader(exchange);
                context.Reject(
                    error: "invalid_dpop_proof",
                    description: "DPoP header is required.");
            }
            return;
        }

        var method = exchange.In.GetHeader<string>("redbHttp.Method") ?? "POST";
        var url = exchange.In.GetHeader<string>("redbHttp.Url") ?? string.Empty;

        var result = await _validator.ValidateAsync(
            proof: proof,
            httpMethod: method,
            httpUri: url,
            ct: context.CancellationToken).ConfigureAwait(false);

        if (!result.IsValid)
        {
            _logger.LogWarning("DPoP proof validation failed: {Error} — {Desc}",
                result.Error, result.ErrorDescription);

            exchange.Properties["identity-event-type"] = redb.Identity.Contracts.Routes.IdentityAuditEventIds.DpopReplayDetected;
            exchange.Properties["identity-event-data"] = new
            {
                Error = result.Error,
                Description = result.ErrorDescription,
            };

            IssueNonceHeader(exchange);
            context.Reject(
                error: result.Error ?? "invalid_dpop_proof",
                description: result.ErrorDescription);
            return;
        }

        // Z4 P2 (RFC 9449 §8): server-side nonce policy. The validator surfaced the parsed
        // claim; this handler decides whether the nonce is acceptable.
        if (_options.RequireNonce)
        {
            if (string.IsNullOrEmpty(result.Nonce) || !_nonceProvider.ValidateNonce(result.Nonce))
            {
                IssueNonceHeader(exchange);
                context.Reject(
                    error: "use_dpop_nonce",
                    description: "DPoP proof is missing a valid server-issued nonce.");
                return;
            }
        }

        // Always rotate the nonce on success so the next proof can adopt a fresh one.
        IssueNonceHeader(exchange);

        // Store jkt for the sign-in handler to bind into the access token.
        context.Transaction.Properties["dpop:jkt"] = result.Jkt!;

        exchange.Properties["identity-event-type"] = redb.Identity.Contracts.Routes.IdentityAuditEventIds.DpopBindingApplied;
        exchange.Properties["identity-event-data"] = new { Jkt = result.Jkt };
    }

    private void IssueNonceHeader(redb.Route.Abstractions.IExchange exchange)
    {
        // The Apply*ResponseHandlers copy this transaction property to the response Headers
        // (RFC 9449 §8). Keeping it here decouples policy from transport vocabulary.
        exchange.Properties["dpop:nonce-to-issue"] = _nonceProvider.IssueNonce();
    }
}
