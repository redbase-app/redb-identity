using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// B9 / BUG-9 — Auth0-style gated enumeration of the calling user's MFA methods.
/// Accepts an encrypted <c>mfa_state</c> token (issued by <see cref="LoginProcessor"/>)
/// and returns the methods embedded in that state. Possession of a valid state proves
/// the caller has already passed first-factor authentication and is therefore allowed
/// to discover which factors are configured for the account.
/// <para>
/// On invalid / expired state returns <c>{"success":false,"error":"invalid_grant"}</c>
/// without distinguishing «no such session» from «session expired».
/// </para>
/// </summary>
internal sealed class MfaListMethodsProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MfaListMethodsProcessor(IServiceProvider sp) => _sp = sp;

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var mfaStateToken = body?.TryGetValue("mfa_state", out var s) == true ? s?.ToString() : null;

        exchange.Out = new Message();

        if (string.IsNullOrEmpty(mfaStateToken))
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = "Missing mfa_state"
            };
            return Task.CompletedTask;
        }

        using var scope = _sp.CreateScope();
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();

        var state = mfaService.UnprotectState(mfaStateToken);
        if (state is null || state.Methods is null)
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_grant",
                ["error_description"] = "MFA session expired or invalid"
            };
            return Task.CompletedTask;
        }

        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["methods"] = state.Methods
        };
        return Task.CompletedTask;
    }
}
