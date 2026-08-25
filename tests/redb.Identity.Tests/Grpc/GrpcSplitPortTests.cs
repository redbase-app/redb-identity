using FluentAssertions;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using redb.Identity.Grpc.Management.V1;
using redb.Identity.Grpc.V1;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// The production port layout: the admin surface on a port of its own, firewalled separately from the
/// protocol surface every relying party calls.
/// <para>
/// Until this fixture existed, <c>EffectiveManagementPort</c> only ever took its <c>null → same port</c>
/// branch. A split that has never run is not a supported configuration, it is a config key that looks
/// like one — and the way it would fail is the worst kind: admin operations quietly still answering on
/// the public port, so the firewall rule protects nothing.
/// </para>
/// </summary>
[Collection("PostgresCollection")]
public class GrpcSplitPortTests : IClassFixture<GrpcSplitPortIdentityFixture>
{
    private readonly GrpcSplitPortIdentityFixture _fixture;

    public GrpcSplitPortTests(GrpcSplitPortIdentityFixture fixture) => _fixture = fixture;

    private const string Users = "/identity.management.v1.Users";

    [Fact]
    public void The_two_surfaces_really_are_on_different_ports()
    {
        _fixture.EffectiveManagementPort.Should().NotBe(_fixture.Port,
            "the rest of this class asserts nothing if the fixture quietly shared one port");
    }

    [Fact]
    public async Task The_admin_surface_answers_on_the_management_port()
    {
        var response = await CallManagement("List", await AdminTokenAsync());

        response.Result.Should().NotBeNull();
    }

    [Fact]
    public async Task The_admin_surface_is_not_reachable_on_the_public_port()
    {
        // The point of splitting the ports. If the admin address answered here too, a firewall rule on the
        // management port would be decoration.
        var act = async () => await _fixture.CallRawAsync(
            $"{Users}/List", Request().ToByteArray(), Bearer(await AdminTokenAsync()));

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.Unimplemented,
            "the public port serves the protocol surface and must not know the admin addresses");
    }

    [Fact]
    public async Task The_protocol_surface_still_answers_on_the_public_port()
    {
        // The other half of the split: moving the admin surface must not move anything else.
        var issued = await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
                Scope = GrpcIdentityFixture.GrantedScope,
            },
            TokenResponse.Parser);

        issued.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task The_gate_is_still_a_gate_on_the_management_port()
    {
        // Splitting ports must not move the authentication step off the path it protects.
        var act = async () => await CallManagement("List", token: null);

        (await act.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
    }

    // ── helpers ───────────────────────────────────────────────

    private static ManagementRequest Request() => new()
    {
        Arguments = JsonParser.Default.Parse<Struct>("""{"offset":0,"count":1}"""),
    };

    private static Metadata? Bearer(string? token) =>
        token is null ? null : new Metadata { { "authorization", "Bearer " + token } };

    private async Task<ManagementResponse> CallManagement(string method, string? token)
    {
        var reply = await _fixture.CallManagementRawAsync(
            $"{Users}/{method}", Request().ToByteArray(), Bearer(token));

        return ManagementResponse.Parser.ParseFrom(reply);
    }

    private async Task<string> AdminTokenAsync()
    {
        var issued = await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
                Scope = GrpcIdentityFixture.GrantedScope,
            },
            TokenResponse.Parser);

        return issued.AccessToken;
    }
}
