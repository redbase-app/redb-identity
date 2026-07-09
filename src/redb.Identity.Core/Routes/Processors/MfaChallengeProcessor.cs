using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for MFA challenge dispatch (SMS/Email).
/// Accepts encrypted <c>mfa_state</c> + <c>method</c> ("sms" or "email"),
/// generates a fresh OTP code, sends it via the registered <see cref="IMfaDeliveryChannel"/>,
/// and returns a NEW encrypted state with the OTP embedded for the verify step.
/// </summary>
internal sealed class MfaChallengeProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MfaChallengeProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var mfaStateToken = body?.TryGetValue("mfa_state", out var s) == true ? s?.ToString() : null;
        var method = body?.TryGetValue("method", out var m) == true ? m?.ToString() : null;

        exchange.Out = new Message();

        if (string.IsNullOrEmpty(mfaStateToken) || string.IsNullOrEmpty(method))
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = "Missing mfa_state or method"
            };
            return;
        }

        using var scope = _sp.CreateScope();
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();

        var state = mfaService.UnprotectState(mfaStateToken);
        if (state is null)
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_grant",
                ["error_description"] = "MFA session expired or invalid"
            };
            return;
        }

        var result = await mfaService.CreateChallengeAsync(
            state.UserId, state.Username ?? "", method, state.ReturnUrl,
            knownMethods: state.Methods, ct).ConfigureAwait(false);

        if (!result.Success)
        {
            var resp = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = result.Error
            };
            if (result.RetryAfterSeconds is { } retry)
                resp["retry_after"] = retry;
            exchange.Out.Body = resp;
            return;
        }

        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["mfa_state"] = result.MfaState,
            ["masked_destination"] = result.MaskedDestination,
            ["method"] = result.Method
        };
    }
}
