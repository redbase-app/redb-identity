using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// C1 — Per-(IP+username) failure counter. Runs AFTER <see cref="LoginProcessor"/> and
/// inspects <c>exchange.Out.Body</c> to decide:
/// <list type="bullet">
///   <item><description><c>success=true</c> → resets the failure bucket so a single
///   legitimate sign-in clears the tally.</description></item>
///   <item><description><c>success=false</c> (any reason: bad password, MFA challenge,
///   any error) → increments the bucket; if the limit is breached, replaces the response
///   with HTTP 429 + <c>Retry-After</c>.</description></item>
/// </list>
/// </summary>
internal sealed class LoginFailureRecorderProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    private readonly ILogger _logger;

    public LoginFailureRecorderProcessor(IServiceProvider sp, ILogger? logger = null)
    {
        _sp = sp;
        _logger = logger ?? NullLogger.Instance;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var store = _sp.GetService<IRateLimitStore>();
        var optsAccessor = _sp.GetService<Microsoft.Extensions.Options.IOptions<RedbIdentityOptions>>();
        if (store is null || optsAccessor is null)
            return;

        var rl = optsAccessor.Value.RateLimit;
        if (!rl.Enabled)
            return;

        var inBody = exchange.In.Body as IDictionary<string, object?>;
        var username = inBody?.TryGetValue("username", out var u) == true ? u?.ToString() : null;
        if (string.IsNullOrWhiteSpace(username))
            return;

        var ip = exchange.In.Headers.TryGetValue("redbHttp.RemoteAddress", out var v) ? v?.ToString() : null;
        if (string.IsNullOrEmpty(ip))
            return;

        var key = $"ipuser:login:{ip}:{username.ToLowerInvariant()}";

        var outBody = exchange.Out?.Body as IDictionary<string, object?>;
        var succeeded = outBody is not null
            && outBody.TryGetValue("success", out var s)
            && s is bool b && b;

        if (succeeded)
        {
            await store.ResetAsync(key, ct);
            return;
        }

        var decision = await store.TryIncrementAsync(key, rl.PerIpUsernameFailures, rl.PerIpUsernameWindow, ct);
        System.Diagnostics.Debug.WriteLine($"[RATE-LIMIT] key={key} allowed={decision.Allowed} count={decision.Count} limit={rl.PerIpUsernameFailures}");
        if (!decision.Allowed)
        {
            _logger.LogWarning(
                "Per-(IP+username) failure ceiling reached: ip={Ip} username={User} count={Count}",
                ip, username, decision.Count);
            // F3 + G4: emit `identity.rate_limit.rejections` with key_dimension=ip_user tag
            // — distinguishes credential-stuffing block-outs from generic per-IP throttle.
            _sp.GetService<IdentityMetrics>()?.RateLimitRejections.Add(
                1,
                new KeyValuePair<string, object?>("key_dimension", "ip_user"),
                new KeyValuePair<string, object?>("endpoint", "login"));
            RateLimitProcessor.EmitTooManyRequests(exchange, decision.RetryAfter, rl.DefaultRetryAfterSeconds);
        }
    }
}
