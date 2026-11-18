using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Registration;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Http.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Nobody registers themselves an administrator.
/// <para>
/// Open dynamic client registration (RFC 7591 §1.2) lets an anonymous caller create a client, and
/// the only limit on what that client may ask for is <c>DynamicRegistrationAllowedScopes</c>. The
/// shipped list includes the granular administrative scopes so the demo suite can probe each admin
/// surface — which also meant that anyone able to reach <c>POST /connect/register</c> could mint a
/// <c>client_credentials</c> client carrying <c>identity:users:write</c>, take a token and delete
/// users. No role, no password, no operator involved.
/// </para>
/// <para>
/// The entitlement gate on user-bound grants cannot reach this: <c>client_credentials</c> has no
/// user to entitle, so the client's own permissions are the whole gate — and those permissions are
/// exactly what registration hands out. The floor therefore sits below deployment policy: while
/// registration is open, administrative scopes are refused whatever the allow-list says.
/// Configuring an initial access token turns registration into the protected mode RFC 7591 defines,
/// and the allow-list governs again.
/// </para>
/// </summary>
public class AnonymousDcrAdminScopeTests
{
    private const string InitialAccessToken = "test-initial-access-token";

    private readonly IOpenIddictApplicationManager _manager = Substitute.For<IOpenIddictApplicationManager>();
    private readonly IRedbService _redb = Substitute.For<IRedbService>();

    /// <summary>A deployment whose allow-list is as permissive as the shipped one.</summary>
    private static RedbIdentityOptions Permissive(string? initialAccessToken = null) => new()
    {
        Features = new IdentityFeatureFlags { EnableDynamicRegistration = true },
        DynamicRegistrationAllowedGrantTypes = ["authorization_code", "client_credentials"],
        DynamicRegistrationAllowedScopes =
            ["openid", "profile", "identity:account", "identity:users:write", "identity:manage", "scim"],
        DynamicRegistrationInitialAccessToken = initialAccessToken,
    };

    private DynamicRegistrationProcessor CreateProcessor(RedbIdentityOptions options)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_manager);
        services.AddSingleton(_redb);
        var sp = services.BuildServiceProvider();

        var context = Substitute.For<IRouteContext>();
        context.GetServiceProvider().Returns(sp);
        context.GetFromRegistry<IServiceScopeFactory>(Arg.Any<string>()).Returns((IServiceScopeFactory?)null);
        context.GetService<IRedbService>().Returns(_redb);
        return new DynamicRegistrationProcessor(context, Options.Create(options));
    }

    private void SetupManager()
    {
        _manager.PopulateAsync(Arg.Any<object>(), Arg.Any<OpenIddictApplicationDescriptor>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                if (ci.Arg<object>() is RedbObject<ApplicationProps> ro)
                {
                    var d = ci.Arg<OpenIddictApplicationDescriptor>();
                    ro.Props.ClientId = d.ClientId;
                    ro.Props.Permissions = d.Permissions.ToArray();
                }
                return ValueTask.CompletedTask;
            });
        _manager.CreateAsync(Arg.Any<object>(), Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(ValueTask.CompletedTask);
        _manager.CreateAsync(Arg.Any<object>(), Arg.Any<CancellationToken>()).Returns(ValueTask.CompletedTask);
        _manager.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<object?>(new RedbObject<ApplicationProps>
            {
                Props = new ApplicationProps { ClientId = ci.Arg<string>() }
            }));
    }

    private static TestExchange Registration(string scope, string? bearer = null)
    {
        var exchange = new TestExchange();
        exchange.In.Body = new DynamicRegistrationRequest
        {
            ClientName = "self-service admin",
            GrantTypes = ["client_credentials"],
            Scope = scope,
        };
        if (bearer is not null) exchange.In.Headers["access_token"] = bearer;
        return exchange;
    }

    private static IDictionary<string, object?> ErrorBody(TestExchange exchange) =>
        exchange.Out!.Body as IDictionary<string, object?>
        ?? throw new InvalidOperationException("the processor answered with a non-error body");

    [Theory]
    [InlineData("identity:users:write")]
    [InlineData("identity:manage")]
    [InlineData("scim")]
    [InlineData("openid identity:users:write")]
    public async Task Open_registration_refuses_administrative_scopes(string scope)
    {
        SetupManager();
        var exchange = Registration(scope);

        await CreateProcessor(Permissive()).Process(exchange);

        ErrorBody(exchange)["error"]!.ToString().Should().Be("invalid_client_metadata",
            "an anonymous caller must not be able to register a client that administers this server");
        await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("openid profile")]
    [InlineData("identity:account")]
    public async Task Open_registration_still_serves_ordinary_clients(string scope)
    {
        SetupManager();
        var exchange = Registration(scope);

        await CreateProcessor(Permissive()).Process(exchange);

        exchange.Out!.Body.Should().NotBeNull();
        (exchange.Out.Body as IDictionary<string, object?>)?.ContainsKey("error").Should().NotBe(true,
            "self-service scopes are what open registration is for - identity:account included");
    }

    [Fact]
    public async Task A_registration_the_deployment_vouched_for_may_ask_for_them()
    {
        SetupManager();
        var exchange = Registration("identity:users:write", bearer: InitialAccessToken);

        await CreateProcessor(Permissive(InitialAccessToken)).Process(exchange);

        (exchange.Out!.Body as IDictionary<string, object?>)?.ContainsKey("error").Should().NotBe(true,
            "with an initial access token the registration is authenticated (RFC 7591 protected mode), "
            + "and the allow-list governs as before");
    }

    [Fact]
    public async Task Without_the_token_the_protected_deployment_refuses_outright()
    {
        SetupManager();
        var exchange = Registration("identity:users:write");

        await CreateProcessor(Permissive(InitialAccessToken)).Process(exchange);

        ErrorBody(exchange)["error"]!.ToString().Should().Be("invalid_token");
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("", "")]
    [InlineData(" ", " ")]
    [InlineData("\t", "")]
    [InlineData(" ", " ")]
    public async Task A_blank_initial_access_token_is_not_configured_and_the_floor_applies(string? configured, string? presented)
    {
        SetupManager();
        var exchange = Registration("identity:users:write", bearer: presented);

        await CreateProcessor(Permissive(configured)).Process(exchange);

        ErrorBody(exchange)["error"]!.ToString().Should().Be("invalid_client_metadata",
            "a blank initial access token is no token: registration is open and administrative scopes are refused");
        ErrorBody(exchange)["error_description"]!.ToString().Should().Contain("require an authenticated registration");
        await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task A_blank_initial_access_token_still_serves_ordinary_clients(string configured)
    {
        SetupManager();
        var exchange = Registration("openid profile", bearer: configured);

        await CreateProcessor(Permissive(configured)).Process(exchange);

        (exchange.Out!.Body as IDictionary<string, object?>)?.ContainsKey("error").Should().NotBe(true,
            "a blank token means open registration, and open registration serves self-service scopes");
    }

    /// <summary>
    /// The same over the wire, for every HTTP version a TLS host serves: the HTTP facade's bearer extraction and
    /// this processor behind a Kestrel endpoint, the initial access token configured as an empty string, and a
    /// request whose Authorization header carries "Bearer " with nothing after it.
    /// </summary>
    [Theory]
    [InlineData("1.1")]
    [InlineData("2.0")]
    public async Task Over_tls_a_blank_initial_access_token_refuses_administrative_scopes(string version)
    {
        SetupManager();
        var processor = CreateProcessor(Permissive(""));
        var port = FreePort();
        var (certPath, certPassword) = SelfSignedPfx();
        try
        {
            await using var context = new RouteContext();
            context.AddComponent(new HttpsComponent { ServerManager = new SharedHttpServerManager(new HttpHostingOptions()) });
            context.AddRoutes(new RegisterRoute(
                $"https:POST:127.0.0.1:{port}/connect/register?inOut=true&ssl=true"
                + $"&sslCertPath={Uri.EscapeDataString(certPath)}&sslCertPassword={Uri.EscapeDataString(certPassword)}",
                processor));
            await context.Start();

            using var handler = new SocketsHttpHandler
            {
                SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
            };
            using var http = new HttpClient(handler);
            using var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, $"https://127.0.0.1:{port}/connect/register")
            {
                Version = Version.Parse(version),
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new StringContent(
                    """{"client_name":"blank-token","grant_types":["client_credentials"],"scope":"identity:users:write"}""",
                    System.Text.Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer ");

            using var response = await http.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            response.Version.Should().Be(Version.Parse(version), "the request must really travel over HTTP/" + version);
            response.StatusCode.Should().Be(System.Net.HttpStatusCode.BadRequest, body);
            body.Should().Contain("invalid_client_metadata").And.Contain("require an authenticated registration",
                "the refusal must come from the floor for anonymous registrants, not from another check");
            await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
            await _manager.DidNotReceive().CreateAsync(Arg.Any<object>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            File.Delete(certPath);
        }
    }

    private sealed class RegisterRoute(string uri, IProcessor processor) : RouteBuilder
    {
        protected override void Configure()
        {
            From(uri)
                .RouteId("test-blank-token-register")
                .Process(HttpIdentityProcessors.ExtractBearerToken)
                .Process(processor)
                .Process(HttpIdentityProcessors.SerializeJsonResponse);
        }
    }

    private static int FreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static (string Path, string Password) SelfSignedPfx()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var certificateRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=localhost", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        const string password = "blank-token-test";
        var path = Path.Combine(Path.GetTempPath(), $"redb-identity-dcr-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, password));
        return (path, password);
    }
}
