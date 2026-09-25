using System.Net.Http.Headers;
using System.Text;
using FluentAssertions;
using Grpc.Core;
using redb.Identity.Grpc.Processors;
using redb.Identity.Http.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using redb.Route.Grpc;
using RouteHttpHeaders = redb.Route.Http.HttpHeaders;
using Xunit;

namespace redb.Identity.Tests.Http;

/// <summary>
/// A status the dispatcher already decided survives the management error table.
/// <para>
/// The table in <c>ManagementErrorCodes</c> exists because controllers report failure as an error
/// document wrapped in a 200. The facades read that document and pick the status. They also read it when
/// the controller dispatcher had written a verdict of its own — <c>NotFound</c> 404 for a path no action
/// matches, <c>InternalError</c> 500 for an action that threw — and since neither string is in the table,
/// both came out as 400. A missing route told the caller their request was malformed; an exception in our
/// own code reached them as their fault, which is exactly how a disabled feature once showed up as a 400
/// while the log held an unhandled exception. On gRPC the same path produced <c>INVALID_ARGUMENT</c>.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class ManagementStatusPreservationTests
{
    private readonly ProductionHttpFixture _fx;

    public ManagementStatusPreservationTests(ProductionHttpFixture fx) => _fx = fx;

    private static byte[] Json(string json) => Encoding.UTF8.GetBytes(json);

    private static readonly byte[] DispatcherNotFound =
        Json("""{"error":"NotFound","message":"No action matches GET /no-such-resource","statusCode":404}""");

    private static readonly byte[] DispatcherInternalError =
        Json("""{"error":"InternalError","message":"An unexpected error occurred","statusCode":500}""");

    /// <summary>The status a response leaves with: the mapper's Out if it made one, else what it was handed.</summary>
    private static int EffectiveHttpStatus(IExchange e)
    {
        var source = e.HasOut && e.Out!.Headers.ContainsKey(RouteHttpHeaders.ResponseCode) ? e.Out! : e.In;
        return Convert.ToInt32(source.Headers[RouteHttpHeaders.ResponseCode]);
    }

    // ── Through the real HTTP pipeline ──────────────────────────────────────────────────

    [Fact]
    public async Task An_unknown_management_path_answers_404()
    {
        using var req = new HttpRequestMessage(System.Net.Http.HttpMethod.Get, "/api/v1/identity/no-such-resource");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().Be(404,
            "the dispatcher found no action for the path and said so; the error table must not turn "
            + "\"no such endpoint\" into \"your request is malformed\"");
    }

    // ── HTTP facade mapper ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Http_keeps_the_dispatchers_404()
    {
        IExchange e = new TestExchange();
        e.In.Body = DispatcherNotFound;
        e.In.Headers[RouteHttpHeaders.ResponseCode] = 404;
        e.In.Headers["status.code"] = 404;

        await HttpIdentityProcessors.MapManagementErrorToHttpStatus(e, CancellationToken.None);

        EffectiveHttpStatus(e).Should().Be(404);
    }

    [Fact]
    public async Task Http_keeps_the_dispatchers_500()
    {
        IExchange e = new TestExchange();
        e.In.Body = DispatcherInternalError;
        e.In.Headers[RouteHttpHeaders.ResponseCode] = 500;
        e.In.Headers["status.code"] = 500;

        await HttpIdentityProcessors.MapManagementErrorToHttpStatus(e, CancellationToken.None);

        EffectiveHttpStatus(e).Should().Be(500,
            "an action that threw is our failure; reporting it as 400 blames the caller for it");
    }

    [Theory]
    [InlineData("not_found", 404)]
    [InlineData("duplicate", 409)]
    [InlineData("weak_password", 400)]
    public async Task Http_still_maps_a_controller_error_document_wrapped_in_200(string error, int expected)
    {
        IExchange e = new TestExchange();
        e.In.Body = Json($$"""{"error":"{{error}}","error_description":"from the controller"}""");
        e.In.Headers[RouteHttpHeaders.ResponseCode] = 200;
        e.In.Headers["status.code"] = 200;

        await HttpIdentityProcessors.MapManagementErrorToHttpStatus(e, CancellationToken.None);

        EffectiveHttpStatus(e).Should().Be(expected,
            "this is the case the table exists for, and it must keep working");
    }

    // ── gRPC facade mapper ──────────────────────────────────────────────────────────────

    private static int GrpcStatusOf(IExchange e)
    {
        var target = e.HasOut ? e.Out! : e.In;
        return Convert.ToInt32(target.Headers[GrpcHeaders.StatusCode]);
    }

    [Fact]
    public async Task Grpc_answers_not_found_for_the_dispatchers_404()
    {
        // The gRPC dispatcher writes only status.code, never redbHttp.ResponseCode.
        IExchange e = new TestExchange();
        e.In.Body = DispatcherNotFound;
        e.In.Headers["status.code"] = 404;

        await GrpcManagementProcessors.MapControllerErrorToGrpcStatus(e, CancellationToken.None);

        GrpcStatusOf(e).Should().Be((int)StatusCode.NotFound);
    }

    [Fact]
    public async Task Grpc_answers_internal_for_the_dispatchers_500()
    {
        IExchange e = new TestExchange();
        e.In.Body = DispatcherInternalError;
        e.In.Headers["status.code"] = 500;

        await GrpcManagementProcessors.MapControllerErrorToGrpcStatus(e, CancellationToken.None);

        GrpcStatusOf(e).Should().Be((int)StatusCode.Internal,
            "INVALID_ARGUMENT would tell the caller to change a request that was never the problem");
    }

    [Fact]
    public async Task Grpc_still_maps_a_controller_error_document_wrapped_in_200()
    {
        IExchange e = new TestExchange();
        e.In.Body = Json("""{"error":"not_found","error_description":"from the controller"}""");
        e.In.Headers["status.code"] = 200;

        await GrpcManagementProcessors.MapControllerErrorToGrpcStatus(e, CancellationToken.None);

        GrpcStatusOf(e).Should().Be((int)StatusCode.NotFound);
    }
}
