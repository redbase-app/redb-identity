using System.Reflection;
using System.Runtime.ExceptionServices;
using FluentAssertions;
using Grpc.Core;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Grpc;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// Ф3 — the steps that bridge what Core expects to what gRPC speaks. Tested directly on an exchange:
/// these are decisions about headers and statuses, and a transport round-trip would only obscure them.
/// </summary>
public class GrpcIdentityProcessorsTests
{
    // ── correlation id ───────────────────────────────────────

    [Fact]
    public async Task A_caller_supplied_correlation_id_is_kept_and_echoed()
    {
        var exchange = NewExchange();
        exchange.In.Headers["X-Correlation-Id"] = "caller-trace-1";

        await Invoke("PropagateCorrelationId", exchange);

        exchange.Properties["identity:correlation-id"].Should().Be("caller-trace-1");
        exchange.In.GetHeader<string>(GrpcHeaders.TrailerPrefix + "x-correlation-id")
            .Should().Be("caller-trace-1", "the caller must be able to stitch its logs to ours");
    }

    [Fact]
    public async Task Reserved_internal_headers_sent_as_metadata_are_stripped_on_ingress()
    {
        // The gRPC connector copies caller metadata and envelope headers into In.Headers verbatim;
        // Core trusts these names (audit attribution, credentials, idempotency operation). Before
        // the strip a caller could sign the audit log with another user's id and a fabricated
        // address by sending them as metadata on Token / Revoke / Introspect.
        var exchange = NewExchange();
        foreach (var name in redb.Identity.Contracts.Routes.IdentityReservedInboundHeaders.Names)
            exchange.In.Headers[name] = "forged";
        exchange.In.Headers["SESSION_USER_ID"] = "forged-upper";
        exchange.In.Headers["Idempotency-Key"] = "legit-key";
        exchange.In.Headers["authorization"] = "Bearer legit";

        await Invoke("PropagateCorrelationId", exchange);

        foreach (var name in redb.Identity.Contracts.Routes.IdentityReservedInboundHeaders.Names)
            exchange.In.Headers.ContainsKey(name).Should().BeFalse($"'{name}' must only ever be set by a facade processor");
        exchange.In.Headers.ContainsKey("SESSION_USER_ID").Should().BeFalse("header names are case-insensitive");
        exchange.In.Headers["Idempotency-Key"].Should().Be("legit-key", "caller metadata that is not reserved stays");
        exchange.In.Headers["authorization"].Should().Be("Bearer legit");
    }

    [Fact]
    public async Task A_correlation_id_is_invented_when_the_caller_sent_none()
    {
        var exchange = NewExchange();

        await Invoke("PropagateCorrelationId", exchange);

        exchange.Properties["identity:correlation-id"].Should().NotBeNull();
        exchange.In.GetHeader<string>(GrpcHeaders.TrailerPrefix + "x-correlation-id")
            .Should().NotBeNullOrEmpty();
    }

    // ── idempotency ──────────────────────────────────────────

    [Fact]
    public async Task The_operation_is_named_so_idempotency_keys_do_not_collide()
    {
        // Core composes its idempotency record name from scope, operation, caller and the caller's key.
        // Without a name every gRPC call would share the bucket "default" and two different operations
        // carrying one Idempotency-Key would collide.
        var exchange = NewExchange();

        await InvokeFactory("TagOperation", "token", exchange);

        exchange.In.GetHeader<string>("operation").Should().Be("token");
    }

    // ── upstream statuses ────────────────────────────────────

    [Theory]
    [InlineData(429, StatusCode.ResourceExhausted)]  // rate limiting
    [InlineData(403, StatusCode.PermissionDenied)]   // scope guard
    [InlineData(503, StatusCode.Unavailable)]        // database outage
    [InlineData(404, StatusCode.NotFound)]
    public async Task A_status_core_decided_reaches_the_caller_as_a_status(int responseCode, StatusCode expected)
    {
        // These arrive as redbHttp.ResponseCode because every processor in Core speaks that vocabulary.
        // Untranslated they would reach the caller as a successful call.
        var exchange = NewExchange();
        exchange.Out = new Message(new Dictionary<string, object?> { ["success"] = false });
        exchange.Out.Headers["redbHttp.ResponseCode"] = responseCode;

        await Invoke("MapErrorToGrpcStatus", exchange);

        exchange.Out.GetHeader<int>(GrpcHeaders.StatusCode).Should().Be((int)expected);
    }

    [Fact]
    public async Task Retry_after_survives_into_a_trailer()
    {
        // Rate limiting says when to come back. A non-OK gRPC reply discards its payload, so that advice
        // has to travel as a trailer or it is lost.
        var exchange = NewExchange();
        exchange.Out = new Message(new Dictionary<string, object?>());
        exchange.Out.Headers["redbHttp.ResponseCode"] = 429;
        exchange.Out.Headers["Retry-After"] = "30";

        await Invoke("MapErrorToGrpcStatus", exchange);

        exchange.Out.GetHeader<string>(GrpcHeaders.TrailerPrefix + "retry-after").Should().Be("30");
    }

    [Fact]
    public async Task A_successful_response_code_leaves_the_status_alone()
    {
        var exchange = NewExchange();
        exchange.Out = new Message(new Dictionary<string, object?> { ["access_token"] = "at" });
        exchange.Out.Headers["redbHttp.ResponseCode"] = 200;

        await Invoke("MapErrorToGrpcStatus", exchange);

        exchange.Out.Headers.Should().NotContainKey(GrpcHeaders.StatusCode);
    }

    [Fact]
    public async Task An_oauth_error_wins_over_the_response_code_and_lands_in_trailers()
    {
        var exchange = NewExchange();
        exchange.Out = new Message(new Dictionary<string, object?>
        {
            ["error"] = "invalid_client",
            ["error_description"] = "Unknown client.",
        });

        await Invoke("MapErrorToGrpcStatus", exchange);

        exchange.Out.GetHeader<int>(GrpcHeaders.StatusCode).Should().Be((int)StatusCode.Unauthenticated);
        exchange.Out.GetHeader<string>(GrpcHeaders.TrailerPrefix + "error").Should().Be("invalid_client");
        exchange.Out.GetHeader<string>(GrpcHeaders.StatusDetail).Should().Be("Unknown client.");
    }

    [Fact]
    public async Task A_rate_limited_answer_keeps_both_its_status_and_its_retry_after()
    {
        // The shape Core actually produces: RateLimitProcessor writes an error document AND a 429 AND a
        // Retry-After. An earlier version read the error first and stopped there, which demoted the answer
        // to InvalidArgument and dropped the backoff advice - and every test that fed only the response
        // code went on passing. So this one feeds all three.
        var exchange = NewExchange();
        exchange.Out = new Message(new Dictionary<string, object?>
        {
            ["success"] = false,
            ["error"] = "rate_limited",
            ["error_description"] = "Too many requests. Please retry later.",
        });
        exchange.Out.Headers["redbHttp.ResponseCode"] = 429;
        exchange.Out.Headers["Retry-After"] = "60";

        await Invoke("MapErrorToGrpcStatus", exchange);

        exchange.Out.GetHeader<int>(GrpcHeaders.StatusCode).Should().Be((int)StatusCode.ResourceExhausted,
            "`rate_limited` is in no RFC 6749 table, so only Core's own 429 can name this status");
        exchange.Out.GetHeader<string>(GrpcHeaders.TrailerPrefix + "retry-after").Should().Be("60");
        exchange.Out.GetHeader<string>(GrpcHeaders.TrailerPrefix + "error").Should().Be("rate_limited");
    }

    // ── the boundary into Core ───────────────────────────────

    [Fact]
    public void An_answer_is_lifted_out_of_the_isolated_exchange()
    {
        var facade = NewExchange();
        var core = NewExchange();
        core.Out = new Message(new Dictionary<string, object?> { ["access_token"] = "at" });
        core.Out.Headers["redbHttp.ResponseCode"] = 200;
        core.Stop();  // the limiter and the granular guard both end this way

        var merged = AdoptCoreAnswer(facade, core);

        merged.Should().BeSameAs(facade);
        facade.IsStopped.Should().BeFalse("a stop Core decided for itself must not end our pipeline");
        facade.In.Body.Should().BeSameAs(core.Out.Body);
        facade.In.Headers.Should().ContainKey("redbHttp.ResponseCode");
    }

    [Fact]
    public void An_unhandled_core_fault_is_not_swallowed_at_the_boundary()
    {
        var facade = NewExchange();
        var core = NewExchange();
        core.Exception = new InvalidOperationException("the store is down");

        var act = () => AdoptCoreAnswer(facade, core);

        act.Should().Throw<InvalidOperationException>("silently adopting a failed call would answer OK");
    }

    [Fact]
    public void A_fault_core_already_handled_is_left_alone()
    {
        // The limiter marks its own short-circuit this way. Its error document is the reply, not a bug.
        var facade = NewExchange();
        var core = NewExchange();
        core.Out = new Message(new Dictionary<string, object?> { ["error"] = "rate_limited" });
        core.Exception = new InvalidOperationException("marker");
        core.ExceptionHandled = true;

        var act = () => AdoptCoreAnswer(facade, core);

        act.Should().NotThrow();
    }

    // ── helpers ───────────────────────────────────────────────

    /// <summary>Calls the merge strategy, unwrapping reflection so a thrown fault keeps its own type.</summary>
    private static IExchange AdoptCoreAnswer(IExchange facade, IExchange core)
    {
        try
        {
            return (IExchange)ProcessorsType.GetMethod("AdoptCoreAnswer")!.Invoke(null, [facade, core])!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }
    }

    private static Exchange NewExchange() => new(new Message(Array.Empty<byte>()));

    private static Task Invoke(string name, IExchange exchange)
    {
        var method = ProcessorsType.GetMethod(name)!;
        return (Task)method.Invoke(null, [exchange, CancellationToken.None])!;
    }

    private static Task InvokeFactory(string name, string argument, IExchange exchange)
    {
        var factory = ProcessorsType.GetMethod(name)!;
        var processor = (Func<IExchange, CancellationToken, Task>)factory.Invoke(null, [argument])!;
        return processor(exchange, CancellationToken.None);
    }

    private static readonly Type ProcessorsType =
        typeof(global::redb.Identity.Grpc.IdentityGrpcTransportOptions).Assembly
            .GetType("redb.Identity.Grpc.Processors.GrpcIdentityProcessors")!;
}
