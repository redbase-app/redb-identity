using FluentAssertions;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.Extensions.Configuration;
using redb.Identity.Grpc.Management.V1;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// What the management surface does when Core was wired without a management authentication processor —
/// a configuration a deployment can reach, and the one where "fails closed" has to be true rather than
/// assumed.
/// <para>
/// Its own class with its own class fixture, deliberately. Booting this second stack inside a test method
/// ran <c>InitializeAsync(ensureCreated)</c> and <c>SyncSchemeAsync</c> against the shared database while
/// other collections were still running, and twelve unrelated HTTP tests failed for it. A fixture in
/// <c>PostgresCollection</c> is serialized against them, which is why every other fixture here is one.
/// </para>
/// </summary>
[Collection("PostgresCollection")]
public class GrpcManagementFailClosedTests : IClassFixture<GrpcManagementWithoutAuthFixture>
{
    private readonly GrpcManagementWithoutAuthFixture _fixture;

    public GrpcManagementFailClosedTests(GrpcManagementWithoutAuthFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task With_no_authentication_route_registered_the_surface_refuses_everything()
    {
        // Core registers direct-vm://identity-auth-management only when it was given a management auth
        // processor. A deployment can wire Core without one and still deploy the gRPC management module —
        // the authentication hop then points at an address nobody serves. Two comments in this codebase
        // assert what happens next, and they disagree with each other; neither was ever executed. If the
        // hop is a no-op on a missing endpoint, every admin operation runs unauthenticated.

        // The decisive question is not which status comes back, it is whether the operation ran.
        // A create either left a row behind or it did not, and no amount of status-reading is as
        // honest as looking.
        var login = "failclosed-" + Guid.NewGuid().ToString("N")[..10];
        var create = new ManagementRequest
        {
            Arguments = JsonParser.Default.Parse<Struct>(
                $$"""{"login":"{{login}}","email":"{{login}}@example.test","password":"Str0ng!Passw0rd"}"""),
        };

        try
        {
            await _fixture.CallManagementRawAsync(
                "/identity.management.v1.Users/Create", create.ToByteArray(),
                new Metadata { { "authorization", "Bearer irrelevant-there-is-no-validator" } });
        }
        catch (RpcException) { /* the refusal is expected; the row check below is the proof */ }

        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddJsonFile("appsettings.json").Build();
        await using var conn = new Npgsql.NpgsqlConnection(config.GetConnectionString("Postgres"));
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "select count(*) from _users where _login = @l";
        cmd.Parameters.AddWithValue("l", login);
        var rows = Convert.ToInt64(await cmd.ExecuteScalarAsync());

        rows.Should().Be(0,
            "an admin create must not persist anything when authentication could not run");

        var request = new ManagementRequest
        {
            Arguments = JsonParser.Default.Parse<Struct>("""{"offset":0,"count":1}"""),
        };

        var act = async () => await _fixture.CallManagementRawAsync(
            "/identity.management.v1.Users/List", request.ToByteArray(),
            new Metadata { { "authorization", "Bearer irrelevant-there-is-no-validator" } });

        // The operation must not execute. Which refusal it is matters less than that it is one.
        var ex = await act.Should().ThrowAsync<RpcException>(
            "an authentication hop that cannot run must stop the call, not wave it through");

        ex.Which.StatusCode.Should().NotBe(StatusCode.OK);    }

}
