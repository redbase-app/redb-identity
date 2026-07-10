using System.Diagnostics.Metrics;
using System.Globalization;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Metrics;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// G4 gap-fill — closes the "metrics" and "Retry-After RFC 7231 format" rows of the
/// rate-limit test matrix. Covers:
/// <list type="bullet">
///   <item><c>RateLimitProcessor</c> increments <c>identity.rate_limit.rejections</c> with
///   <c>key_dimension=ip</c> when the per-IP ceiling is breached.</item>
///   <item><c>LoginFailureRecorderProcessor</c> increments the same counter with
///   <c>key_dimension=ip_user</c> so SRE dashboards can distinguish credential-stuffing
///   blocks from generic per-IP throttle.</item>
///   <item>The emitted <c>Retry-After</c> header is a valid RFC 7231 §7.1.3
///   <c>delta-seconds</c> value (<c>1*DIGIT</c>, positive) regardless of store-supplied
///   TTL, with fallback to <see cref="RateLimitOptions.DefaultRetryAfterSeconds"/>.</item>
/// </list>
/// </summary>
public sealed class RateLimitMetricsAndRetryAfterTests
{
    // ── Helpers ─────────────────────────────────────────────────

    private static IExchange MakeIpExchange(string ip)
    {
        var msg = new Message();
        msg.Headers["redbHttp.RemoteAddress"] = ip;
        return new Exchange(msg) { Pattern = ExchangePattern.InOnly };
    }

    private static IExchange MakeLoginExchange(string ip, string username, bool success)
    {
        var msg = new Message
        {
            Body = new Dictionary<string, object?> { ["username"] = username }
        };
        msg.Headers["redbHttp.RemoteAddress"] = ip;
        var ex = new Exchange(msg) { Pattern = ExchangePattern.InOut };
        ex.Out = new Message
        {
            Body = new Dictionary<string, object?> { ["success"] = success }
        };
        return ex;
    }

    private static IServiceProvider BuildSp(
        RateLimitOptions rl,
        IRateLimitStore store,
        IdentityMetrics? metrics)
    {
        var opts = new RedbIdentityOptions { RateLimit = rl };
        var sc = new ServiceCollection();
        sc.AddSingleton<IRateLimitStore>(store);
        sc.AddSingleton<IOptions<RedbIdentityOptions>>(Options.Create(opts));
        if (metrics is not null)
            sc.AddSingleton(metrics);
        return sc.BuildServiceProvider();
    }

    /// <summary>
    /// Wires a <see cref="MeterListener"/> onto the <see cref="IdentityMetrics.MeterName"/>
    /// meter and captures every <c>identity.rate_limit.rejections</c> measurement with its
    /// tag set. Returns a list the test can inspect after running the SUT.
    /// </summary>
    private static (IdentityMetrics Metrics, List<(long Value, Dictionary<string, object?> Tags)> Measurements, MeterListener Listener)
        BuildCapturedMetrics()
    {
        var metrics = new IdentityMetrics();
        var captured = new List<(long, Dictionary<string, object?>)>();

        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == IdentityMetrics.MeterName
                    && instrument.Name == "identity.rate_limit.rejections")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var dict = new Dictionary<string, object?>(tags.Length);
            for (var i = 0; i < tags.Length; i++)
                dict[tags[i].Key] = tags[i].Value;
            captured.Add((value, dict));
        });
        listener.Start();

        return (metrics, captured, listener);
    }

    // ── Metrics — per-IP bucket ─────────────────────────────────

    [Fact]
    public async Task RateLimitProcessor_OverLimit_IncrementsRejectionsCounter_WithIpDimension()
    {
        var (metrics, captured, listener) = BuildCapturedMetrics();
        using var _l = listener;
        using var _m = metrics;

        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 1, DefaultRetryAfterSeconds = 60 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store, metrics);
        var p = new RateLimitProcessor(sp, "token", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));

        await p.Process(MakeIpExchange("1.2.3.4")); // first — passes
        await p.Process(MakeIpExchange("1.2.3.4")); // second — denied

        captured.Should().HaveCount(1,
            "exactly one rejection must be emitted for the single over-limit request");
        captured[0].Value.Should().Be(1);
        captured[0].Tags.Should().ContainKey("key_dimension").WhoseValue.Should().Be("ip");
        captured[0].Tags.Should().ContainKey("bucket").WhoseValue.Should().Be("token");
    }

    // ── Metrics — per-(IP+user) bucket ──────────────────────────

    [Fact]
    public async Task LoginFailureRecorder_BreachCeiling_IncrementsRejectionsCounter_WithIpUserDimension()
    {
        var (metrics, captured, listener) = BuildCapturedMetrics();
        using var _l = listener;
        using var _m = metrics;

        var rl = new RateLimitOptions
        {
            Enabled = true,
            PerIpUsernameFailures = 2,
            PerIpUsernameWindow = TimeSpan.FromMinutes(15),
            DefaultRetryAfterSeconds = 30
        };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store, metrics);
        var p = new LoginFailureRecorderProcessor(sp);

        // Two failures below ceiling — no rejection.
        await p.Process(MakeLoginExchange("1.1.1.1", "alice", success: false));
        await p.Process(MakeLoginExchange("1.1.1.1", "alice", success: false));
        captured.Should().BeEmpty("no metric until the ceiling is breached");

        // Third failure breaches the ceiling.
        await p.Process(MakeLoginExchange("1.1.1.1", "alice", success: false));

        captured.Should().HaveCount(1);
        captured[0].Tags.Should().ContainKey("key_dimension").WhoseValue.Should().Be("ip_user");
        captured[0].Tags.Should().ContainKey("endpoint").WhoseValue.Should().Be("login");
    }

    // ── Retry-After — RFC 7231 delta-seconds ────────────────────

    [Fact]
    public async Task RateLimit429_RetryAfter_IsPositiveIntegerSeconds()
    {
        // RFC 7231 §7.1.3: Retry-After = HTTP-date / delta-seconds; the latter is 1*DIGIT.
        // Our implementation always emits delta-seconds → must parse as a non-negative int.
        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 1, DefaultRetryAfterSeconds = 45 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store, metrics: null);
        var p = new RateLimitProcessor(sp, "any", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));

        await p.Process(MakeIpExchange("9.9.9.9"));
        var denied = MakeIpExchange("9.9.9.9");
        await p.Process(denied);

        denied.Out!.Headers.Should().ContainKey("Retry-After");
        var raw = denied.Out.Headers["Retry-After"]!.ToString()!;

        int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var delta)
            .Should().BeTrue(
                "Retry-After must be pure delta-seconds (1*DIGIT, no decimals / signs / whitespace); " +
                $"was '{raw}'");
        delta.Should().BePositive(
            "delta-seconds must be > 0 so clients can actually wait");
        // Bounded by the sliding-window length (1 min) — a broken implementation that sent
        // >= 3600 would effectively black-hole the client.
        delta.Should().BeLessThanOrEqualTo(60);
    }

    [Fact]
    public async Task RateLimit429_RetryAfter_FallsBackToDefault_WhenStoreHasNoHint()
    {
        // Store returns decision with RetryAfter=Zero → processor must fall back to the
        // configured default, not emit "0" (which clients typically retry immediately,
        // defeating the purpose of the throttle).
        var rl = new RateLimitOptions { Enabled = true, DefaultRetryAfterSeconds = 90 };
        var store = new HintlessDenyingStore();
        var sp = BuildSp(rl, store, metrics: null);
        var p = new RateLimitProcessor(sp, "any", _ => 1, _ => TimeSpan.FromMinutes(1));

        var ex = MakeIpExchange("7.7.7.7");
        await p.Process(ex);

        ex.Out!.Headers["Retry-After"].Should().Be("90");
    }

    /// <summary>
    /// Test double: always denies, always reports zero TTL. Exercises the fallback path in
    /// <see cref="RateLimitProcessor.EmitTooManyRequests"/>.
    /// </summary>
    private sealed class HintlessDenyingStore : IRateLimitStore
    {
        public Task<RateLimitDecision> TryIncrementAsync(string key, int limit, TimeSpan window, CancellationToken ct = default)
            => Task.FromResult(new RateLimitDecision(Allowed: false, Count: limit + 1, RetryAfter: TimeSpan.Zero));

        public Task ResetAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
    }
}
