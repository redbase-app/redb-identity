using FluentAssertions;
using Grpc.Core;
using redb.Identity.Grpc.V1;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// Ф4 — the per-IP limiter, over gRPC, for real. Core keys it on <c>redbHttp.RemoteAddress</c>, a header
/// no gRPC call has of its own: the listener synthesizes it from the connection peer because the facade
/// asks for <c>EmitHttpCompatHeaders</c>. If that bridge ever breaks, the limiter does not fail loudly —
/// it silently stops protecting the gRPC port, and every other test in this suite still passes. This is
/// the one that would not.
/// </summary>
[Collection("PostgresCollection")]
public class GrpcRateLimitTests : IClassFixture<GrpcThrottledIdentityFixture>
{
    private readonly GrpcThrottledIdentityFixture _fixture;

    public GrpcRateLimitTests(GrpcThrottledIdentityFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task A_caller_over_the_per_ip_limit_is_told_to_back_off()
    {
        RpcException? rejection = null;

        // A couple more than the limit: enough to cross it, few enough that the failure message names a
        // number rather than "somewhere in a hundred calls".
        for (var attempt = 1; attempt <= GrpcThrottledIdentityFixture.PerIpPerMinute + 2; attempt++)
        {
            try
            {
                await _fixture.CallAsync("Token",
                    new TokenRequest
                    {
                        GrantType = "client_credentials",
                        ClientId = GrpcIdentityFixture.ClientId,
                        ClientSecret = GrpcIdentityFixture.ClientSecret,
                        Scope = GrpcIdentityFixture.GrantedScope,
                    },
                    TokenResponse.Parser);
            }
            catch (RpcException ex) when (ex.StatusCode == StatusCode.ResourceExhausted)
            {
                rejection = ex;
                break;
            }
        }

        rejection.Should().NotBeNull(
            "the per-IP limit is {0}/minute, so a run of {1} calls from one address must be cut short",
            GrpcThrottledIdentityFixture.PerIpPerMinute,
            GrpcThrottledIdentityFixture.PerIpPerMinute + 2);

        // 429 in the HTTP facade, ResourceExhausted here — the same verdict, spelled in the caller's
        // protocol rather than translated back through a status code they would have to know about.
        rejection!.Trailers.GetValue("error").Should().Be("rate_limited");

        // A non-OK reply discards its payload, so "come back in N seconds" only survives as a trailer.
        rejection.Trailers.GetValue("retry-after").Should().NotBeNullOrEmpty(
            "a limiter that will not say when to retry leaves the caller guessing");
    }
}
