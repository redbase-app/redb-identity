using Microsoft.Extensions.Configuration;
using redb.Identity.Core.Models;
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
/// Ф6 — the management surface over gRPC. The tests that matter here are not the happy path: an admin API
/// that works is easy, an admin API that refuses correctly is the whole job. So the shape of this file is
/// three refusals and one verdict-parity check, with the happy path present only to prove the refusals
/// are refusing something that would otherwise have worked.
/// </summary>
[Collection("PostgresCollection")]
public class GrpcManagementTests : IClassFixture<GrpcIdentityFixture>
{
    private readonly GrpcIdentityFixture _fixture;

    public GrpcManagementTests(GrpcIdentityFixture fixture) => _fixture = fixture;

    private const string Service = "/identity.management.v1.Users";

    // ── the gate ─────────────────────────────────────────────

    [Fact]
    public async Task Without_a_token_an_admin_operation_is_refused_not_executed()
    {
        var act = async () => await CallAsync("List", new { offset = 0, count = 5 }, token: null);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.Unauthenticated,
            "an unauthenticated admin call must be stopped at the gate, not answered");
    }

    [Fact]
    public async Task A_garbage_token_is_refused()
    {
        var act = async () => await CallAsync("List", new { offset = 0, count = 5 }, "not-a-token");

        (await act.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
    }

    [Fact]
    public async Task A_token_that_may_read_is_refused_a_write()
    {
        // The narrow client holds identity:users:read and nothing else. Read passes, write must not —
        // otherwise the granular table is decorative on this transport.
        var narrow = await NarrowTokenAsync();

        var read = async () => await CallAsync("List", new { offset = 0, count = 1 }, narrow);
        await read.Should().NotThrowAsync("identity:users:read authorises reading users");

        var write = async () => await CallAsync("Delete", new { id = "999999" }, narrow);

        var ex = await write.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.PermissionDenied,
            "read does not imply write; the refusal must be PermissionDenied, not a 200 with an error body");
        ex.Which.Trailers.GetValue("error").Should().Be("insufficient_scope");
    }

    // ── the surface works at all ─────────────────────────────

    [Fact]
    public async Task An_admin_token_lists_users()
    {
        var response = await CallAsync("List", new { offset = 0, count = 5 }, await AdminTokenAsync());

        // Whatever the store holds, the answer is a decoded protobuf carrying a real JSON value — which is
        // what proves the Struct round-trip rather than the count of users.
        response.Result.Should().NotBeNull();
        response.Result.KindCase.Should().BeOneOf(Value.KindOneofCase.StructValue, Value.KindOneofCase.ListValue);
    }

    [Fact]
    public async Task A_controller_error_arrives_as_a_status_not_as_a_successful_body()
    {
        // Users.Get on an id that does not exist: the controller answers `error = "not_found"` with no
        // status of its own. Untranslated it would reach the caller as a successful call.
        var act = async () => await CallAsync("Get", new { id = "999999999" }, await AdminTokenAsync());

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.NotFound);
    }

    [Fact]
    public async Task A_forged_dispatch_header_cannot_redirect_the_call()
    {
        // The controller dispatcher routes on a `dispatch-method` header, and that name is not reserved by
        // the connector — a caller can put it in gRPC metadata and it reaches the exchange. If it survived,
        // the escalation is direct: authorize as Users/List (a read the narrow token holds) and execute
        // Users.Delete (a write it does not). The facade overwrites the header before dispatch; this test
        // is what keeps that true, because the defence is an ordering and orderings get edited.
        var narrow = await NarrowTokenAsync();

        var metadata = new Metadata { { "dispatch-method", "Users.Delete" } };
        metadata.Add("authorization", "Bearer " + narrow);

        var request = new ManagementRequest
        {
            Arguments = JsonParser.Default.Parse<Struct>("""{"offset":0,"count":1}"""),
        };

        var reply = await _fixture.CallManagementRawAsync($"{Service}/List", request.ToByteArray(), metadata);
        var response = ManagementResponse.Parser.ParseFrom(reply);

        // The address decides, not the header: this ran List, which the narrow token may do.
        response.Result.Should().NotBeNull("the call must run the operation its address names");
        response.Result.KindCase.Should().BeOneOf(Value.KindOneofCase.StructValue, Value.KindOneofCase.ListValue);
    }

    [Fact]
    public async Task An_idempotency_key_makes_a_repeated_create_one_create()
    {
        // Claimed in the package README and never tested. It has to work through two translations: the
        // caller sends `idempotency-key` as gRPC metadata (HTTP/2 lowercases it), the connector puts that
        // into the exchange headers, and Core reads `Idempotency-Key` — a different spelling. If the
        // header dictionary were case-sensitive anywhere along that path, replays would silently create a
        // second user instead of returning the first.
        var admin = await AdminTokenAsync();
        var login = "idem-" + Guid.NewGuid().ToString("N")[..10];
        var key = Guid.NewGuid().ToString("N");

        var first = await CreateUser(admin, login, key);
        var second = await CreateUser(admin, login, key);

        var firstId = first.Result.StructValue.Fields["Id"].NumberValue;
        var secondId = second.Result.StructValue.Fields["Id"].NumberValue;

        secondId.Should().Be(firstId,
            "the replay must return the original record, not create a second one");

        // And the contrast, so the assertion above cannot pass for the wrong reason: a DIFFERENT key is a
        // different request, so the same login is now a genuine duplicate and must be refused. If the key
        // were being ignored entirely, this call would replay too and quietly return the same record.
        var act = async () => await CreateUser(admin, login, Guid.NewGuid().ToString("N"));

        (await act.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.AlreadyExists,
                "a fresh key means a fresh request, and this login already exists");


    }

    private async Task<ManagementResponse> CreateUser(string token, string login, string idempotencyKey)
    {
        var metadata = new Metadata
        {
            { "authorization", "Bearer " + token },
            { "idempotency-key", idempotencyKey },
        };

        var request = new ManagementRequest
        {
            Arguments = JsonParser.Default.Parse<Struct>(
                $$"""{"login":"{{login}}","email":"{{login}}@example.test","password":"Str0ng!Passw0rd"}"""),
        };

        var reply = await _fixture.CallManagementRawAsync(
            $"{Service}/Create", request.ToByteArray(), metadata);

        return ManagementResponse.Parser.ParseFrom(reply);
    }

    // ── verdict parity, the acceptance criterion ─────────────

    [Fact]
    public async Task The_scope_gate_decides_by_scope_and_nothing_else()
    {
        // Both transports consult one table in Core (Ф5), so the property to assert here is that this
        // transport actually consults it: the same operation is refused for a narrow token and waved
        // through for an admin one, and the refusal comes from the gate rather than from the controller.
        var narrow = await NarrowTokenAsync();
        var admin = await AdminTokenAsync();

        var refused = async () => await CallAsync("Delete", new { id = "999999" }, narrow);
        (await refused.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.PermissionDenied);

        // The admin token clears the gate. What happens afterwards is the controller's business — deleting
        // a user that is not there is idempotent here, so this call simply succeeds. The assertion is only
        // that no gate refused it.
        RpcException? failure = null;
        try { await CallAsync("Delete", new { id = "999999" }, admin); }
        catch (RpcException ex) { failure = ex; }

        failure?.StatusCode.Should().NotBe(StatusCode.PermissionDenied,
            "identity:manage authorises this operation; a refusal here would mean the gate ignores scope");
        failure?.StatusCode.Should().NotBe(StatusCode.Unauthenticated,
            "the token is valid; a refusal here would mean the gate ignores the token");
    }

    // ── helpers ───────────────────────────────────────────────

    private async Task<ManagementResponse> CallAsync(string method, object arguments, string? token)
    {
        var request = new ManagementRequest
        {
            Arguments = JsonParser.Default.Parse<Struct>(System.Text.Json.JsonSerializer.Serialize(arguments)),
        };

        var metadata = new Metadata();
        if (token is not null) metadata.Add("authorization", "Bearer " + token);

        var reply = await _fixture.CallManagementRawAsync($"{Service}/{method}", request.ToByteArray(), metadata);
        return ManagementResponse.Parser.ParseFrom(reply);
    }

    private Task<string> AdminTokenAsync() =>
        TokenAsync(GrpcIdentityFixture.ClientId, GrpcIdentityFixture.ClientSecret, GrpcIdentityFixture.GrantedScope);

    private Task<string> NarrowTokenAsync() =>
        TokenAsync(GrpcIdentityFixture.NarrowClientId, GrpcIdentityFixture.NarrowClientSecret,
            GrpcIdentityFixture.NarrowScope);

    private async Task<string> TokenAsync(string clientId, string secret, string scope)
    {
        var issued = await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = clientId,
                ClientSecret = secret,
                Scope = scope,
            },
            TokenResponse.Parser);

        return issued.AccessToken;
    }
}
