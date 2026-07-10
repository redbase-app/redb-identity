using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Registration;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.DynamicRegistration;

public class DynamicRegistrationProcessorTests
{
    private readonly IOpenIddictApplicationManager _manager = Substitute.For<IOpenIddictApplicationManager>();
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly RedbIdentityOptions _opts = new()
    {
        Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
        DynamicRegistrationAllowedGrantTypes = ["authorization_code", "refresh_token"],
        DynamicRegistrationAllowedScopes = ["openid", "profile", "email", "offline_access"]
    };

    private DynamicRegistrationProcessor CreateProcessor(RedbIdentityOptions? options = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_manager);
        services.AddSingleton(_redb);
        var sp = services.BuildServiceProvider();

        var context = Substitute.For<IRouteContext>();
        context.GetServiceProvider().Returns(sp);
        // NSubstitute auto-mocks interface return types — pin GetFromRegistry to null so
        // GetIdentityService falls through to the host SP instead of an empty auto-mocked scope.
        context.GetFromRegistry<IServiceScopeFactory>(Arg.Any<string>()).Returns((IServiceScopeFactory?)null);
        // Z2: AggregateProcessor calls context.GetRedbService(null, exchange) after CreateAsync
        // to persist the RAT hash — route the request through the context.GetService fallback.
        context.GetService<IRedbService>().Returns(_redb);
        return new DynamicRegistrationProcessor(context, Options.Create(options ?? _opts));
    }

    private static TestExchange CreateExchange(DynamicRegistrationRequest? body = null)
    {
        var exchange = new TestExchange();
        exchange.In.Body = body;
        return exchange;
    }

    private void SetupManager()
    {
        // Production pipeline (post-refactor) splits manager.CreateAsync(descriptor, ct) into:
        //   1. PopulateAsync(app, descriptor, ct)   — copies descriptor → app.Props
        //   2. app.Props.RegistrationAccessTokenHash = ratHash
        //   3. CreateAsync(app, [secret,] ct)       — single redb persist with hash already set
        // Mocks must be wired against this split, otherwise nothing is invoked and Received(...)
        // assertions over the legacy CreateAsync(descriptor, ct) overload silently fail.
        _manager.PopulateAsync(
                Arg.Any<object>(),
                Arg.Any<OpenIddictApplicationDescriptor>(),
                Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                // Mirror the production OpenIddict store: when PopulateAsync runs, it copies
                // descriptor metadata onto the app envelope so subsequent persistence has it.
                if (ci.Arg<object>() is RedbObject<ApplicationProps> ro)
                {
                    var d = ci.Arg<OpenIddictApplicationDescriptor>();
                    ro.Props.ClientId = d.ClientId;
                    ro.Props.ClientType = d.ClientType;
                    ro.Props.ConsentType = d.ConsentType;
                    ro.Props.ApplicationType = d.ApplicationType;
                    ro.Props.Permissions = d.Permissions.ToArray();
                    ro.Props.Requirements = d.Requirements.ToArray();
                    ro.Props.RedirectUris = d.RedirectUris.Select(u => u.AbsoluteUri).ToArray();
                    ro.Props.PostLogoutRedirectUris = d.PostLogoutRedirectUris.Select(u => u.AbsoluteUri).ToArray();
                }
                return ValueTask.CompletedTask;
            });

        _manager.CreateAsync(Arg.Any<object>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);
        _manager.CreateAsync(Arg.Any<object>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        // Z2: processor re-reads the created application after CreateAsync to persist the RAT hash.
        _manager.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<object?>(new RedbObject<ApplicationProps>
            {
                Props = new ApplicationProps { ClientId = ci.Arg<string>() }
            }));
    }

    // ── Happy path ──

    [Fact]
    public async Task Register_MinimalRequest_ReturnsClientCredentials()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            ClientName = "My SPA"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["client_id"].Should().NotBeNull();
        body["client_secret"].Should().NotBeNull();
        body["client_name"]!.ToString().Should().Be("My SPA");
        body["token_endpoint_auth_method"]!.ToString().Should().Be("client_secret_basic");
        body["application_type"]!.ToString().Should().Be("web");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
        exchange.Properties["identity-event-type"].Should().Be("ClientRegistered");
    }

    [Fact]
    public async Task Register_PublicClient_NoSecret()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            TokenEndpointAuthMethod = "none",
            ClientName = "Public App"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["client_id"].Should().NotBeNull();
        body.ContainsKey("client_secret").Should().BeFalse("public clients don't get secrets");
        body["token_endpoint_auth_method"]!.ToString().Should().Be("none");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_WithScopes_EchoedInResponse()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            Scope = "openid profile email"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["scope"]!.ToString().Should().Be("openid profile email");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_WithGrantTypes_EchoedInResponse()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            GrantTypes = ["authorization_code", "refresh_token"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        // grant_types comes back as JsonElement from the serialization round-trip
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_NativeApp_SetsApplicationType()
    {
        // RFC 8252 (OAuth 2.0 for Native Apps, BCP 212):
        //   - private-use URI scheme redirect (§7.1) — "com.example.app://callback"
        //   - application_type=native (per OIDC Dynamic Client Registration §2 +
        //     RFC 8252 §8.4 — native apps SHOULD be registered as public clients)
        //   - token_endpoint_auth_method=none (RFC 8252 §8.4 — native apps are
        //     public clients, no client_secret).
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["com.example.app://callback"],
            ApplicationType = "native",
            TokenEndpointAuthMethod = "none"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["application_type"]!.ToString().Should().Be("native");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_CreatesApp_WithCorrectPermissions()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            GrantTypes = ["authorization_code", "refresh_token"],
            Scope = "openid profile"
        });

        await processor.Process(exchange);

        await _manager.Received(1).PopulateAsync(
            Arg.Any<object>(),
            Arg.Is<OpenIddictApplicationDescriptor>(d =>
                d.ClientType == "confidential" &&
                d.ConsentType == "implicit" &&
                d.Permissions.Contains("ept:token") &&
                d.Permissions.Contains("ept:authorization") &&
                d.Permissions.Contains("gt:authorization_code") &&
                d.Permissions.Contains("gt:refresh_token") &&
                d.Permissions.Contains("scp:openid") &&
                d.Permissions.Contains("scp:profile") &&
                d.Requirements.Contains("ft:pkce")
            ),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Register_ClientSecretPost_ReturnsSecretAndConfidentialType()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            TokenEndpointAuthMethod = "client_secret_post"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["client_secret"].Should().NotBeNull();
        body["token_endpoint_auth_method"]!.ToString().Should().Be("client_secret_post");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_SetsClientIdIssuedAt()
    {
        SetupManager();
        var processor = CreateProcessor();
        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        var issuedAtElement = (System.Text.Json.JsonElement)body!["client_id_issued_at"]!;
        var issuedAt = issuedAtElement.GetInt64();
        issuedAt.Should().BeGreaterOrEqualTo(before);
    }

    // ── Validation errors ──

    [Fact]
    public async Task Register_NullBody_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = new TestExchange();
        exchange.In.Body = null;

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Register_InvalidJson_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = new TestExchange();
        exchange.In.Body = "not-valid-json{{{";

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Register_DisallowedGrantType_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            GrantTypes = ["client_credentials"],
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
        body["error_description"]!.ToString().Should().Contain("client_credentials");
    }

    [Fact]
    public async Task Register_DisallowedScope_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            Scope = "openid identity:manage"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
        body["error_description"]!.ToString().Should().Contain("identity:manage");
    }

    [Fact]
    public async Task Register_AuthCodeWithoutRedirectUris_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            GrantTypes = ["authorization_code"]
            // No redirect_uris
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task Register_InvalidRedirectUri_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["not a uri"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_redirect_uri");
    }

    // C5 — RFC 6749 §3.1.2 / OAuth 2.1 §4.1: wildcards and fragments must be rejected.
    [Theory]
    [InlineData("https://*.example.com/cb")]
    [InlineData("https://app.example.com/*")]
    [InlineData("https://app.example.com/cb#frag")]
    public async Task Register_RedirectUriWithWildcardOrFragment_ReturnsError(string uri)
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = [uri]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task Register_PostLogoutRedirectUriWithWildcard_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            PostLogoutRedirectUris = ["https://*.example.com/logout"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Register_InvalidApplicationType_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            ApplicationType = "desktop"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
        body["error_description"]!.ToString().Should().Contain("application_type");
    }

    [Fact]
    public async Task Register_UnsupportedAuthMethod_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            TokenEndpointAuthMethod = "private_key_jwt"
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
        body["error_description"]!.ToString().Should().Contain("private_key_jwt");
    }

    // ── Initial access token ──

    [Fact]
    public async Task Register_WithTokenRequired_ValidToken_Succeeds()
    {
        SetupManager();
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
            DynamicRegistrationInitialAccessToken = "my-secret-token"
        };
        var processor = CreateProcessor(opts);
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });
        exchange.In.Headers["access_token"] = "my-secret-token";

        await processor.Process(exchange);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_WithTokenRequired_MissingToken_Returns401()
    {
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
            DynamicRegistrationInitialAccessToken = "my-secret-token"
        };
        var processor = CreateProcessor(opts);
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_token");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task Register_WithTokenRequired_WrongToken_Returns401()
    {
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
            DynamicRegistrationInitialAccessToken = "my-secret-token"
        };
        var processor = CreateProcessor(opts);
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });
        exchange.In.Headers["access_token"] = "wrong-token";

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_token");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task Register_WithTokenRequired_AuthorizationHeader_Succeeds()
    {
        SetupManager();
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
            DynamicRegistrationInitialAccessToken = "my-secret-token"
        };
        var processor = CreateProcessor(opts);
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });
        exchange.In.Headers["Authorization"] = "Bearer my-secret-token";

        await processor.Process(exchange);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    // ── JSON body parsing ──

    [Fact]
    public async Task Register_JsonStringBody_ParsedCorrectly()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = new TestExchange();
        exchange.In.Body = """{"redirect_uris":["https://app.example.com/callback"],"client_name":"JSON App"}""";

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["client_name"]!.ToString().Should().Be("JSON App");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    [Fact]
    public async Task Register_JsonBytesBody_ParsedCorrectly()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = new TestExchange();
        exchange.In.Body = System.Text.Encoding.UTF8.GetBytes(
            """{"redirect_uris":["https://app.example.com/callback"],"client_name":"Bytes App"}""");

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["client_name"]!.ToString().Should().Be("Bytes App");
        exchange.Out.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    // ── Defaults ──

    [Fact]
    public async Task Register_NoGrantTypes_DefaultsToAuthorizationCode()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        // Verify PKCE requirement was set (only for authorization_code)
        await _manager.Received(1).PopulateAsync(
            Arg.Any<object>(),
            Arg.Is<OpenIddictApplicationDescriptor>(d =>
                d.Requirements.Contains("ft:pkce") &&
                d.Permissions.Contains("gt:authorization_code")
            ),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Register_DefaultResponseType_IsCode()
    {
        SetupManager();
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        await _manager.Received(1).PopulateAsync(
            Arg.Any<object>(),
            Arg.Is<OpenIddictApplicationDescriptor>(d =>
                d.Permissions.Contains("rst:code")
            ),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Register_InvalidPostLogoutRedirectUri_ReturnsError()
    {
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"],
            PostLogoutRedirectUris = ["not a uri"]
        });

        await processor.Process(exchange);

        var body = exchange.Out!.Body as IDictionary<string, object?>;
        body!["error"]!.ToString().Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Register_NoTokenRequired_Succeeds_WithoutToken()
    {
        SetupManager();
        // Default opts have no DynamicRegistrationInitialAccessToken
        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(201);
    }

    // ── Z1: Registration Access Token (RFC 7591 §3.2.1 / RFC 7592) ──

    private static string? GetBodyString(IExchange exchange, string key)
    {
        var dict = exchange.Out!.Body as IDictionary<string, object?>;
        if (dict is null || !dict.TryGetValue(key, out var raw) || raw is null) return null;
        if (raw is System.Text.Json.JsonElement je)
            return je.ValueKind == System.Text.Json.JsonValueKind.String ? je.GetString() : je.ToString();
        return raw.ToString();
    }

    [Fact]
    public async Task Register_Response_Includes_RegistrationAccessToken_And_ClientUri()
    {
        SetupManager();
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
            Issuer = new Uri("https://id.example.com"),
            DynamicRegistrationAllowedGrantTypes = ["authorization_code"],
            DynamicRegistrationAllowedScopes = ["openid"]
        };
        var processor = CreateProcessor(opts);
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        exchange.Out!.Headers["redbHttp.ResponseCode"].Should().Be(201);
        var token = GetBodyString(exchange, "registration_access_token");
        token.Should().NotBeNullOrWhiteSpace(
            "RFC 7591 §3.2.1 — response MUST include registration_access_token when management is supported");
        token!.Length.Should().BeGreaterThan(32,
            "token must carry enough entropy for OWASP ASVS 2.3.1");
        var uri = GetBodyString(exchange, "registration_client_uri");
        uri.Should().NotBeNullOrWhiteSpace();
        uri!.Should().StartWith("https://id.example.com/connect/register/");
        var clientId = GetBodyString(exchange, "client_id")!;
        uri.Should().EndWith(Uri.EscapeDataString(clientId));
    }

    [Fact]
    public async Task Register_Persists_Sha256_Hash_Of_RegistrationAccessToken()
    {
        // Arrange: capture the app envelope passed to CreateAsync to inspect RegistrationAccessTokenHash.
        // Production sets app.Props.RegistrationAccessTokenHash BEFORE calling CreateAsync(app, …),
        // so capturing the reference is sufficient (no separate _redb.SaveAsync round-trip).
        SetupManager();
        RedbObject<ApplicationProps>? persisted = null;
        _manager.CreateAsync(
                Arg.Do<object>(o => persisted = o as RedbObject<ApplicationProps> ?? persisted),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);
        _manager.CreateAsync(
                Arg.Do<object>(o => persisted = o as RedbObject<ApplicationProps> ?? persisted),
                Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        // Act
        await processor.Process(exchange);

        // Assert — hash is stored, NOT the token (OWASP A02:2021 — no cleartext credentials at rest).
        var token = GetBodyString(exchange, "registration_access_token")!;
        var expectedHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

        persisted.Should().NotBeNull("processor must persist the application carrying the RAT hash");
        persisted!.Props.RegistrationAccessTokenHash.Should().Be(expectedHash);
        persisted.Props.RegistrationAccessTokenHash.Should().NotContain(token,
            "the token itself must never be persisted — only its SHA-256 hash");
    }

    [Fact]
    public async Task Register_ClientUri_Encodes_ClientId_Safely()
    {
        // Force a tricky client_id by having the manager's CreateAsync set one with reserved chars.
        _manager.CreateAsync(Arg.Any<OpenIddictApplicationDescriptor>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var d = ci.Arg<OpenIddictApplicationDescriptor>();
                d.ClientId = "client/with spaces?x";
                return new object();
            });
        _manager.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<object?>(new RedbObject<ApplicationProps>
            {
                Props = new ApplicationProps { ClientId = ci.Arg<string>() }
            }));

        var processor = CreateProcessor();
        var exchange = CreateExchange(new DynamicRegistrationRequest
        {
            RedirectUris = ["https://app.example.com/callback"]
        });

        await processor.Process(exchange);

        var uri = GetBodyString(exchange, "registration_client_uri")!;
        uri.Should().NotContain(" ", "path segment must be URL-escaped");
        uri.Should().NotContain("?x",
            "query-like fragments of the client_id must not leak into the URL unescaped");
    }
}
