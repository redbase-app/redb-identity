using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// C1 — Per-IP rate-limit guard. Reads the (already trust-resolved by C2) client IP from
/// <c>redbHttp.RemoteAddress</c> and consults <see cref="IRateLimitStore"/>. On limit
/// breach, short-circuits the pipeline with an HTTP 429 + <c>Retry-After</c> response and
/// stops further processors from running.
/// </summary>
internal sealed class RateLimitProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    private readonly string _bucketTag;
    private readonly Func<RateLimitOptions, int> _limitSelector;
    private readonly Func<RateLimitOptions, TimeSpan> _windowSelector;
    private readonly ILogger _logger;

    public RateLimitProcessor(
        IServiceProvider sp,
        string bucketTag,
        Func<RateLimitOptions, int> limitSelector,
        Func<RateLimitOptions, TimeSpan> windowSelector,
        ILogger? logger = null)
    {
        _sp = sp;
        _bucketTag = bucketTag;
        _limitSelector = limitSelector;
        _windowSelector = windowSelector;
        _logger = logger ?? NullLogger.Instance;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var store = _sp.GetService<IRateLimitStore>();
        var optsAccessor = _sp.GetService<Microsoft.Extensions.Options.IOptions<RedbIdentityOptions>>();
        if (store is null || optsAccessor is null)
            return; // Misconfigured — fail open rather than block legitimate traffic.

        var rl = optsAccessor.Value.RateLimit;
        if (!rl.Enabled)
            return;

        var ip = ResolveClientIp(exchange);
        if (string.IsNullOrEmpty(ip))
            return; // No IP (e.g. internal direct-vm caller) — skip.

        var key = $"ip:{_bucketTag}:{ip}";
        var decision = await store.TryIncrementAsync(key, _limitSelector(rl), _windowSelector(rl), ct);

        if (!decision.Allowed)
        {
            _logger.LogWarning(
                "RateLimit triggered: bucket={Bucket} ip={Ip} count={Count} retryAfter={RetryAfterSec}s",
                _bucketTag, ip, decision.Count, (int)decision.RetryAfter.TotalSeconds);
            // F3 + G4: emit `identity.rate_limit.rejections` with key_dimension=ip tag so
            // SRE dashboards can slice per-IP throttle activity from per-(IP+user) activity.
            _sp.GetService<IdentityMetrics>()?.RateLimitRejections.Add(
                1,
                new KeyValuePair<string, object?>("key_dimension", "ip"),
                new KeyValuePair<string, object?>("bucket", _bucketTag));
            EmitTooManyRequests(exchange, decision.RetryAfter, rl.DefaultRetryAfterSeconds);
        }
    }

    private static string? ResolveClientIp(IExchange exchange)
    {
        if (exchange.In.Headers.TryGetValue("redbHttp.RemoteAddress", out var v) && v is not null)
            return v.ToString();
        return null;
    }

    internal static void EmitTooManyRequests(IExchange exchange, TimeSpan retryAfter, int defaultRetryAfterSeconds)
    {
        var seconds = retryAfter > TimeSpan.Zero
            ? (int)Math.Ceiling(retryAfter.TotalSeconds)
            : defaultRetryAfterSeconds;

        exchange.Out = new Message
        {
            Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "rate_limited",
                ["error_description"] = "Too many requests. Please retry later."
            }
        };
        exchange.Out.Headers["redbHttp.ResponseCode"] = 429;
        exchange.Out.Headers["redbHttp.ResponseContentType"] = "application/json";
        exchange.Out.Headers["Retry-After"] = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);

        // Mark as handled so downstream processors don't keep running.
        exchange.Exception = new RateLimitedException();
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }
}

/// <summary>Marker exception used to short-circuit the route pipeline when a rate limit fires.</summary>
internal sealed class RateLimitedException : Exception
{
    public RateLimitedException() : base("Rate limit exceeded") { }
}
