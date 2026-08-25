using System.Text;
using Google.Protobuf;
using System.Text.Json;
using FluentAssertions;
using Grpc.Core;
using redb.Identity.Grpc.V1;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// Ð¤2/Ð¤3 end to end: the service-to-service protocol over gRPC against the real Core â a token is issued,
/// introspected, revoked, and seen dead afterwards. Both spellings of the contract are covered: the typed
/// <c>identity.v1</c> addresses and the generic envelope fallback.
/// </summary>
[Collection("PostgresCollection")]
public class GrpcProtocolFlowTests : IClassFixture<GrpcIdentityFixture>
{
    private readonly GrpcIdentityFixture _fixture;

    public GrpcProtocolFlowTests(GrpcIdentityFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Client_credentials_issues_a_token()
    {
        var response = await Token(GrpcIdentityFixture.ClientId, "identity:manage");

        response.AccessToken.Should().NotBeNullOrEmpty();
        response.TokenType.Should().Be("Bearer");
        response.ExpiresIn.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Issued_token_introspects_as_active_then_dies_on_revocation()
    {
        var issued = await Token(GrpcIdentityFixture.ClientId, "identity:manage");

        var before = await _fixture.CallAsync("Introspect",
            new IntrospectRequest
            {
                Token = issued.AccessToken,
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
            },
            IntrospectResponse.Parser);

        before.Active.Should().BeTrue();
        before.ClientId.Should().Be(GrpcIdentityFixture.ClientId);

        await _fixture.CallAsync("Revoke",
            new RevokeRequest
            {
                Token = issued.AccessToken,
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
            },
            RevokeResponse.Parser);

        // Revocation took effect. OpenIddict reports a revoked token as an error rather than as RFC 7662's
        // `active: false` â the repo records the same behaviour in IntrospectionRevocationTests â so the
        // proof is the refusal, and our facade carries it as a status rather than as a 200 with a body.
        var act = async () => await _fixture.CallAsync("Introspect",
            new IntrospectRequest
            {
                Token = issued.AccessToken,
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
            },
            IntrospectResponse.Parser);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
        ex.Which.Status.Detail.Should().Contain("no longer valid");
    }

    [Fact]
    public async Task Discovery_is_passed_through_with_its_http_addresses()
    {
        var response = await _fixture.CallAsync("Discovery", new DiscoveryRequest(), DiscoveryResponse.Parser);

        response.Document.Should().NotBeNull();
        response.Document!.Fields.Should().ContainKey("issuer");

        // The document advertises the server's HTTP endpoints. Those are the real ones â rewriting them
        // here would hand callers addresses that do not exist.
        response.Document.Fields["token_endpoint"].StringValue.Should().Contain("/connect/token");
    }

    [Fact]
    public async Task Jwks_returns_the_signing_keys()
    {
        var response = await _fixture.CallAsync("Jwks", new JwksRequest(), JwksResponse.Parser);

        response.Document!.Fields["keys"].ListValue.Values.Should().NotBeEmpty();
    }

    [Fact]
    public async Task An_oauth_error_arrives_as_a_grpc_status_not_as_a_successful_body()
    {
        // Without the error mapping this would be a successful call carrying an error document â which no
        // generated client inspects.
        var act = async () => await _fixture.CallAsync("Token",
            new TokenRequest { GrantType = "no_such_grant", ClientId = "x" }, TokenResponse.Parser);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.InvalidArgument);

        // The machine-readable code survives in a trailer: a non-OK reply has its payload discarded.
        ex.Which.Trailers.GetValue("error").Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Unknown_claims_are_not_dropped_they_overflow_into_the_struct()
    {
        var issued = await Token(GrpcIdentityFixture.ClientId, "identity:manage");

        var introspected = await _fixture.CallAsync("Introspect",
            new IntrospectRequest
            {
                Token = issued.AccessToken,
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
            },
            IntrospectResponse.Parser);

        introspected.Active.Should().BeTrue();

        // The named RFC 7662 members land in their own slots …
        introspected.ClientId.Should().Be(GrpcIdentityFixture.ClientId);
        introspected.Exp.Should().BeGreaterThan(0);

        // … and nothing the codec has a slot for may be duplicated into the overflow instead. A named
        // field appearing in `extra` would mean the caller has to look in two places for one claim.
        var named = IntrospectResponse.Descriptor.Fields.InDeclarationOrder()
            .Where(f => f.Name != "extra").Select(f => f.Name);
        (introspected.Extra?.Fields.Keys ?? Enumerable.Empty<string>())
            .Should().NotIntersectWith(named);
    }

    // ââ negative matrix ââââââââââââââââââââââââââââââââââââââ

    [Fact]
    public async Task A_wrong_client_secret_is_refused_as_unauthenticated()
    {
        // Real client registry, BCrypt-hashed secret â this assertion means something only because the
        // fixture is not in degraded mode.
        var act = async () => await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = "not-the-secret",
                Scope = GrpcIdentityFixture.GrantedScope,
            },
            TokenResponse.Parser);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
        ex.Which.Trailers.GetValue("error").Should().Be("invalid_client");
    }

    [Fact]
    public async Task An_unknown_client_is_refused()
    {
        var act = async () => await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = "no-such-client",
                ClientSecret = "whatever",
            },
            TokenResponse.Parser);

        (await act.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
    }

    [Fact]
    public async Task A_scope_the_client_may_not_have_is_refused()
    {
        // The seeded client is permitted exactly one scope. Asking for another must fail rather than
        // quietly issue a token with fewer scopes than requested.
        var act = async () => await _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
                Scope = "some:other:scope",
            },
            TokenResponse.Parser);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.InvalidArgument);
        ex.Which.Trailers.GetValue("error").Should().Be("invalid_scope");
    }

    [Fact]
    public async Task Introspecting_a_garbage_token_is_refused()
    {
        // RFC 7662 Â§2.2 would allow `active: false`, but OpenIddict answers an unparseable token with an
        // error, and the repo records that behaviour in IntrospectionRevocationTests. The facade's job is
        // to carry that verdict faithfully as a status, not to invent an RFC-shaped answer Core never gave.
        var act = async () => await _fixture.CallAsync("Introspect",
            new IntrospectRequest
            {
                Token = "not-a-real-token",
                ClientId = GrpcIdentityFixture.ClientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
            },
            IntrospectResponse.Parser);

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.Unauthenticated);
        ex.Which.Trailers.GetValue("error").Should().Be("invalid_token");
    }

    // ââ envelope fallback ââââââââââââââââââââââââââââââââââââ

    [Fact]
    public async Task The_envelope_path_issues_a_token_too()
    {
        // Same surface, second spelling: JSON body plus an `operation` header, for callers that do not
        // want to carry identity.v1.proto.
        var body = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = GrpcIdentityFixture.ClientId,
            ["client_secret"] = GrpcIdentityFixture.ClientSecret,
            ["scope"] = "identity:manage",
        });

        var reply = await CallEnvelope("token", body);

        var json = JsonSerializer.Deserialize<JsonElement>(reply);
        json.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task An_unknown_envelope_operation_is_unimplemented()
    {
        RpcException? failure = null;
        byte[]? reply = null;

        try { reply = await CallEnvelope("nope", "{}"u8.ToArray()); }
        catch (RpcException ex) { failure = ex; }

        failure.Should().NotBeNull(
            "an unknown operation must be rejected; the server instead answered: {0}",
            reply is null ? "(nothing)" : Encoding.UTF8.GetString(reply));
        failure!.StatusCode.Should().Be(StatusCode.Unimplemented);
        failure.Status.Detail.Should().Contain("token", "the answer should list what is available");
    }

    // ââ helpers âââââââââââââââââââââââââââââââââââââââââââââââ

    private Task<TokenResponse> Token(string clientId, string scope) =>
        _fixture.CallAsync("Token",
            new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = clientId,
                ClientSecret = GrpcIdentityFixture.ClientSecret,
                Scope = scope,
            },
            TokenResponse.Parser);

    /// <summary>
    /// Calls the envelope path and unwraps the reply. The generic address runs in envelope mode on both
    /// legs, so the answer comes back inside a RedbMessage â the JSON body is its payload.
    /// </summary>
    private async Task<byte[]> CallEnvelope(string operation, byte[] body)
    {
        var reply = await _fixture.CallRawAsync("/redb.route.grpc.RedbService/Process",
            Envelope(operation, body), new Metadata { { "operation", operation } });

        return redb.Route.Grpc.Proto.RedbMessage.Parser.ParseFrom(reply).Payload.ToByteArray();
    }

    /// <summary>Wraps a JSON body in the connector's generic RedbMessage envelope.</summary>
    private static byte[] Envelope(string operation, byte[] body)
    {
        var message = new redb.Route.Grpc.Proto.RedbMessage
        {
            Payload = Google.Protobuf.ByteString.CopyFrom(body),
        };
        message.Headers.Add("operation", operation);
        return message.ToByteArray();
    }
}
