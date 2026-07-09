using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Route.Abstractions;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Transport-agnostic entry point for processing OAuth/OIDC requests
/// through the OpenIddict Server pipeline from an <see cref="IExchange"/>.
/// <para>
/// Usage in a route definition:
/// <code>
/// From("direct-vm://identity-token")
///     .Process(async (exchange, ct) =>
///     {
///         var handler = context.GetService&lt;RedbRouteOpenIddictServerHandler&gt;();
///         await handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Token, ct);
///     });
/// </code>
/// </para>
/// <para>
/// <b>Lifetime (A2):</b> registered as Singleton. Per-exchange Scoped dependencies
/// (<see cref="IOpenIddictServerFactory"/>, <see cref="IOpenIddictServerDispatcher"/>) are
/// resolved through <see cref="IExchange.ServiceProvider"/> when available — redb.Route opens
/// a fresh <see cref="IServiceScope"/> per exchange and exposes it on the exchange — falling
/// back to a private scope created via <see cref="IServiceScopeFactory"/>. This avoids the
/// captive-Scoped-into-Singleton trap.
/// </para>
/// </summary>
public sealed class RedbRouteOpenIddictServerHandler
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _options;
    private readonly ILogger<RedbRouteOpenIddictServerHandler>? _logger;

    public RedbRouteOpenIddictServerHandler(
        IServiceScopeFactory scopeFactory,
        IOptionsMonitor<OpenIddictServerOptions> options,
        ILogger<RedbRouteOpenIddictServerHandler>? logger = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    /// <summary>
    /// Processes an OAuth/OIDC request through the OpenIddict Server pipeline.
    /// The exchange body is parsed by registered Extract handlers, and the
    /// response is written to <see cref="IExchange.Out"/> by Apply handlers.
    /// </summary>
    /// <param name="exchange">Route exchange containing the OAuth request.</param>
    /// <param name="endpointType">The OAuth endpoint type to process.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task ProcessAsync(
        IExchange exchange,
        OpenIddictServerEndpointType endpointType,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(exchange);

        // Prefer the per-exchange scope opened by redb.Route IF it actually carries our
        // OpenIddict registrations. In .tpkg mode the route-context host SP does NOT have
        // Identity registrations — only the Identity child SP (captured via _scopeFactory)
        // does. Probe the exchange SP for the marker service and fall back to the private
        // scope on miss. This keeps the in-process / single-SP path on the per-exchange
        // scope (correct OpenIddict scoping) while making the isolated-module path work.
        var exchangeSp = exchange.ServiceProvider;
        IServiceScope? privateScope = null;
        IServiceProvider sp;
        if (exchangeSp is not null && exchangeSp.GetService<IOpenIddictServerFactory>() is not null)
        {
            sp = exchangeSp;
        }
        else
        {
            privateScope = _scopeFactory.CreateScope();
            sp = privateScope.ServiceProvider;
        }

        try
        {
            _logger?.LogDebug(
                "OpenIddict ProcessAsync start: endpoint={Endpoint} issuer={Issuer} hasExchangeSp={HasExchangeSp}",
                endpointType, _options.CurrentValue.Issuer, exchangeSp is not null);

            var factory = sp.GetRequiredService<IOpenIddictServerFactory>();
            var dispatcher = sp.GetRequiredService<IOpenIddictServerDispatcher>();

            var transaction = await factory.CreateTransactionAsync();
            transaction.EndpointType = endpointType;
            transaction.CancellationToken = cancellationToken;
            transaction.BaseUri = _options.CurrentValue.Issuer;
            transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;

            var context = new ProcessRequestContext(transaction);
            try
            {
                await dispatcher.DispatchAsync(context);
            }
            catch (Exception dispatchEx)
            {
                _logger?.LogError(dispatchEx,
                    "OpenIddict DispatchAsync threw for endpoint={Endpoint}. " +
                    "context.Error={Error} context.ErrorDescription={Desc} context.IsRejected={Rejected}",
                    endpointType, context.Error, context.ErrorDescription, context.IsRejected);
                throw;
            }

            _logger?.LogDebug(
                "OpenIddict ProcessAsync done: endpoint={Endpoint} handled={Handled} skipped={Skipped} rejected={Rejected} error={Error} desc={Desc} hasResponse={HasResp}",
                endpointType, context.IsRequestHandled, context.IsRequestSkipped, context.IsRejected,
                context.Error, context.ErrorDescription, transaction.Response is not null);

            // If Apply handlers wrote the response, we're done.
            if (context.IsRequestHandled || context.IsRequestSkipped)
                return;

            // The pipeline was rejected (e.g., unsupported_grant_type) but the error
            // response was not written to the exchange by Apply handlers (the built-in
            // error Apply path may not fire for all rejection scenarios).
            // Write the error response directly.
            if (context.IsRejected)
            {
                var response = new OpenIddictResponse
                {
                    Error = context.Error,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                };

                // RFC 6749 §4.1.2.1: authorization endpoint errors MUST be reported via the
                // validated redirect_uri whenever one is present (e.g. prompt=none → login_required,
                // consent_required from HandleAuthorizationRequest). Fall back to JSON only when
                // we genuinely have no redirect target (validation failed before redirect_uri
                // could be resolved). Preserve `state` so the client can correlate the response.
                //
                // SECURITY (RFC 6749 §3.1.2.4 / §4.1.2.1): NEVER redirect to a redirect_uri the
                // server rejected. Using `transaction.Request.RedirectUri` unconditionally is an
                // open-redirect — the request URI is attacker-supplied and only becomes safe to
                // use once OpenIddict's validation handlers confirm it matches a registered URI
                // for the client. If OpenIddict rejected the redirect_uri itself (ID2043/2052/2095/2100
                // family), we must respond inline (JSON / problem details) and NOT bounce the
                // browser through the attacker-controlled location with an `error=...` query.
                var isRedirectUriRejection = !string.IsNullOrEmpty(context.ErrorUri) && (
                    context.ErrorUri.Contains("ID2043", StringComparison.Ordinal) ||
                    context.ErrorUri.Contains("ID2052", StringComparison.Ordinal) ||
                    context.ErrorUri.Contains("ID2095", StringComparison.Ordinal) ||
                    context.ErrorUri.Contains("ID2100", StringComparison.Ordinal));

                // OIDC §3.1.2.6: login_required / consent_required have two reasonable
                // user-agent flows; pick the right one per the flag the request carried.
                //
                //   prompt=none (prompt_none=true on exchange)
                //     The RP opted into "yes/no, never show UI" — the error MUST flow back
                //     to redirect_uri so the RP can fall back to its own UX. Don't defer.
                //
                //   prompt=login (force_login=true on exchange)
                //     Per §3.1.2.6, the OP "SHOULD prompt the User for reauthentication"
                //     but if it cannot, "it MUST return an error, typically login_required".
                //     The "session present, RP wants re-auth" scenario is the canonical
                //     case: the user is already authenticated, so /login UI would be a
                //     loop (the cookie reauthenticates them automatically). Surface
                //     login_required on the redirect_uri so the RP can drive the re-auth
                //     decision (clear its own session, re-issue authorize without prompt,
                //     etc). Don't defer.
                //
                //   neither flag (no prompt, or prompt with no special value)
                //     The user simply has no session — redirect to the local /login page
                //     so they can complete authentication; otherwise the RP gets
                //     login_required and the user has no way to fix it from the RP side.
                //     Defer.
                var promptNone = exchange.Properties.TryGetValue("prompt_none", out var pn) && pn is true;
                var forceLogin = exchange.Properties.TryGetValue("force_login", out var fl) && fl is true;
                var interactiveDeferred =
                    !promptNone
                    && !forceLogin
                    && (string.Equals(context.Error, "login_required", StringComparison.Ordinal)
                        || string.Equals(context.Error, "consent_required", StringComparison.Ordinal));

                if (endpointType == OpenIddictServerEndpointType.Authorization
                    && !isRedirectUriRejection
                    && !interactiveDeferred
                    && !string.IsNullOrEmpty(transaction.Request?.RedirectUri)
                    && exchange.In.Headers.ContainsKey(redb.Route.Http.HttpHeaders.Method))
                {
                    if (!string.IsNullOrEmpty(transaction.Request.State))
                        response.State = transaction.Request.State;

                    WriteAuthorizationErrorRedirect(
                        exchange,
                        transaction.Request.RedirectUri!,
                        transaction.Request.ResponseMode,
                        response);
                    return;
                }

                RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, response);
                return;
            }

            // Fallback: response exists on transaction but wasn't written to exchange
            if (transaction.Response != null && exchange.Out?.Body == null)
            {
                RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, transaction.Response);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex,
                "RedbRouteOpenIddictServerHandler.ProcessAsync FAILED: endpoint={Endpoint} type={ExType} msg={Msg}",
                endpointType, ex.GetType().FullName, ex.Message);
            throw;
        }
        finally
        {
            privateScope?.Dispose();
        }
    }

    /// <summary>
    /// Builds the RFC 6749 §4.1.2.1 error redirect for the authorization endpoint:
    /// 302 to <c>redirect_uri</c> with <c>error</c>/<c>error_description</c>/<c>state</c> on the
    /// query string (default) or the URL fragment (when <c>response_mode=fragment</c>).
    /// </summary>
    private static void WriteAuthorizationErrorRedirect(
        IExchange exchange,
        string redirectUri,
        string? responseMode,
        OpenIddictResponse response)
    {
        var sb = new System.Text.StringBuilder();
        var first = true;
        foreach (var p in response.GetParameters())
        {
            var value = p.Value.Value?.ToString();
            if (value is null) continue;
            if (!first) sb.Append('&');
            first = false;
            sb.Append(Uri.EscapeDataString(p.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(value));
        }
        var payload = sb.ToString();

        string location;
        if (string.Equals(responseMode, "fragment", StringComparison.Ordinal))
        {
            location = redirectUri + "#" + payload;
        }
        else
        {
            var sep = redirectUri.Contains('?') ? "&" : "?";
            location = redirectUri + sep + payload;
        }

        if (exchange.Out is null)
        {
            exchange.Pattern = ExchangePattern.InOut;
            exchange.Out = exchange.In.Clone();
            exchange.Out.Body = null;
            exchange.Out.Headers.Clear();
        }

        var msg = exchange.Out!;
        msg.Body = Array.Empty<byte>();
        msg.Headers[redb.Route.Http.HttpHeaders.ResponseCode] = 302;
        msg.Headers["Location"] = location;
    }
}
