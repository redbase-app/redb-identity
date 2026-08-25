using FluentAssertions;
using redb.Identity.Grpc;
using redb.Identity.Grpc.V1;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// Ф1 — the codec between the published <c>identity.v1</c> contract and the parameter/answer shapes the
/// <c>direct-vm://identity-*</c> boundary speaks. Mapping is descriptor-driven, so these tests are really
/// about the rules: what is omitted, what overflows into the Struct, what survives a type it cannot hold.
/// </summary>
public class IdentityGrpcCodecTests
{
    // ── request → parameters ─────────────────────────────────

    [Fact]
    public void Named_fields_become_parameters_under_their_proto_names()
    {
        var request = new TokenRequest
        {
            GrantType = "client_credentials",
            ClientId = "svc",
            ClientSecret = "s3cret",
            Scope = "identity:manage",
        };

        var parameters = IdentityGrpcCodec.ToParameters(request);

        parameters.Should().Contain("grant_type", "client_credentials");
        parameters.Should().Contain("client_id", "svc");
        parameters.Should().Contain("client_secret", "s3cret");
        parameters.Should().Contain("scope", "identity:manage");
    }

    [Fact]
    public void Empty_fields_are_omitted_not_sent_blank()
    {
        // OAuth distinguishes «absent» from «present and empty»: sending code="" on a
        // client_credentials request would make the server reject a request it should accept.
        var parameters = IdentityGrpcCodec.ToParameters(new TokenRequest { GrantType = "client_credentials" });

        parameters.Should().ContainKey("grant_type");
        parameters.Should().NotContainKey("code");
        parameters.Should().NotContainKey("refresh_token");
        parameters.Should().NotContainKey("username");
    }

    [Fact]
    public void Additional_map_is_merged_flat()
    {
        // An extension parameter is a parameter — the boundary must not see a nested bag.
        var request = new TokenRequest { GrantType = "urn:example:custom" };
        request.Additional.Add("resource", "https://api.example.com");
        request.Additional.Add("audience", "orders");

        var parameters = IdentityGrpcCodec.ToParameters(request);

        parameters.Should().Contain("resource", "https://api.example.com");
        parameters.Should().Contain("audience", "orders");
        parameters.Should().NotContainKey("additional");
    }

    // ── answer → response ────────────────────────────────────

    [Fact]
    public void Named_response_fields_are_filled_by_proto_name()
    {
        var answer = new Dictionary<string, object?>
        {
            ["access_token"] = "at",
            ["token_type"] = "Bearer",
            ["expires_in"] = 3600L,
            ["scope"] = "openid",
        };

        var response = new TokenResponse();
        IdentityGrpcCodec.Populate(response, answer, "extra");

        response.AccessToken.Should().Be("at");
        response.TokenType.Should().Be("Bearer");
        response.ExpiresIn.Should().Be(3600);
        response.Scope.Should().Be("openid");
        response.Extra.Should().BeNull("nothing was left over");
    }

    [Fact]
    public void Unknown_keys_overflow_into_the_struct_instead_of_being_dropped()
    {
        // Introspection extensions (RFC 7662 §2.2) and vendor claims are open sets. Dropping them would
        // lose data the caller explicitly asked for.
        var answer = new Dictionary<string, object?>
        {
            ["access_token"] = "at",
            ["x_tenant"] = "acme",
            ["x_quota"] = 42L,
        };

        var response = new TokenResponse();
        IdentityGrpcCodec.Populate(response, answer, "extra");

        response.AccessToken.Should().Be("at");
        response.Extra.Should().NotBeNull();
        response.Extra!.Fields["x_tenant"].StringValue.Should().Be("acme");
        response.Extra.Fields["x_quota"].NumberValue.Should().Be(42);
    }

    [Fact]
    public void Repeated_fields_accept_a_list_and_a_single_value()
    {
        var many = new IntrospectResponse();
        IdentityGrpcCodec.Populate(many, new Dictionary<string, object?>
        {
            ["active"] = true,
            ["aud"] = new object?[] { "api-a", "api-b" },
        }, "extra");

        many.Active.Should().BeTrue();
        many.Aud.Should().Equal("api-a", "api-b");

        // OpenIddict flattens a single-element audience to a bare string; the contract still says repeated.
        var one = new IntrospectResponse();
        IdentityGrpcCodec.Populate(one, new Dictionary<string, object?> { ["aud"] = "api-a" }, "extra");

        one.Aud.Should().Equal("api-a");
    }

    [Fact]
    public void Numbers_and_booleans_survive_their_wire_representations()
    {
        var response = new IntrospectResponse();
        IdentityGrpcCodec.Populate(response, new Dictionary<string, object?>
        {
            ["active"] = "true",     // a processor may hand back the string form
            ["exp"] = 1_700_000_000L,
            ["iat"] = 1_699_999_000d, // JSON numbers arrive as double when not integral
        }, "extra");

        response.Active.Should().BeTrue();
        response.Exp.Should().Be(1_700_000_000);
        response.Iat.Should().Be(1_699_999_000);
    }

    [Fact]
    public void A_value_the_field_cannot_hold_falls_through_to_the_struct()
    {
        // Better than failing the call: the caller still sees the value, just not in the typed slot.
        var response = new IntrospectResponse();
        IdentityGrpcCodec.Populate(response, new Dictionary<string, object?>
        {
            ["exp"] = "not-a-number",
            ["active"] = true,
        }, "extra");

        response.Active.Should().BeTrue();
        response.Exp.Should().Be(0);
        response.Extra!.Fields["exp"].StringValue.Should().Be("not-a-number");
    }

    [Fact]
    public void Nested_objects_and_arrays_become_struct_values()
    {
        var response = new UserInfoResponse();
        IdentityGrpcCodec.Populate(response, new Dictionary<string, object?>
        {
            ["sub"] = "user-1",
            ["roles"] = new object?[] { "admin", "ops" },
            ["address"] = new Dictionary<string, object?> { ["country"] = "RU" },
        }, "claims");

        response.Sub.Should().Be("user-1");
        response.Claims!.Fields["roles"].ListValue.Values.Select(v => v.StringValue)
            .Should().Equal("admin", "ops");
        response.Claims.Fields["address"].StructValue.Fields["country"].StringValue.Should().Be("RU");
    }

    [Fact]
    public void Document_responses_pass_the_answer_through_verbatim()
    {
        // Discovery advertises the server's HTTP addresses — those are the real ones, and this facade
        // does not rewrite them.
        var answer = new Dictionary<string, object?>
        {
            ["issuer"] = "https://id.example.com",
            ["token_endpoint"] = "https://id.example.com/connect/token",
        };

        var response = new DiscoveryResponse();
        IdentityGrpcCodec.PopulateDocument(response, answer, "document");

        response.Document!.Fields["issuer"].StringValue.Should().Be("https://id.example.com");
        response.Document.Fields["token_endpoint"].StringValue
            .Should().Be("https://id.example.com/connect/token");
    }

    [Fact]
    public void Empty_answer_leaves_the_response_empty()
    {
        var response = new RevokeResponse();

        // RFC 7009 §2.2: a successful revocation carries no content. Nothing to map, nothing to fail on.
        IdentityGrpcCodec.Populate(response, new Dictionary<string, object?>(), "extra");

        response.CalculateSize().Should().Be(0);
    }
}

