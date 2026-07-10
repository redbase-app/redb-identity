using FluentAssertions;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Management;

/// <summary>
/// C12 regression: a confidential application created via the management API must be
/// usable for client_credentials authentication via the token endpoint.
///
/// Before the fix, <see cref="redb.Identity.Core.Routes.Processors.ApplicationManagementProcessor"/>
/// hashed the secret with a custom PBKDF2 hasher and persisted the row directly via
/// <c>IRedbService.SaveAsync</c>, bypassing OpenIddict. The token endpoint validates the secret
/// with OpenIddict's BCrypt hasher — algorithms did not match, so the credentials were unusable.
/// </summary>
[Collection("ProductionBootstrap")]
public class ApplicationManagementClientSecretE2ETests
{
    private readonly ProductionBootstrapFixture _fx;

    public ApplicationManagementClientSecretE2ETests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task CreatedClient_CanAuthenticate_ViaClientCredentials()
    {
        // 1. Create client through management API (the path users hit via REST).
        var clientId = $"c12-mgmt-{Guid.NewGuid():N}";
        const string clientSecret = "Sup3rS3cret-!@#";

        var createBody = new CreateApplicationRequest
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            ClientType = "confidential",
            DisplayName = "C12 management-api created",
            Permissions =
            [
                "ept:token",
                "gt:client_credentials"
            ]
        };

        var createExchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            createBody,
            new Dictionary<string, object?> { ["operation"] = "create" });

        var createOut = createExchange.HasOut ? createExchange.Out!.Body : createExchange.In.Body;
        createOut.Should().BeOfType<ApplicationResponse>(
            $"create should succeed; got {createOut?.GetType().Name}: {createOut}");

        // 2. Use the *plain* secret to obtain an access_token.
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);

        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        tokenResponse.Should().NotContainKey("error",
            because: $"client created via management API must authenticate; got {(tokenResponse.ContainsKey("error_description") ? tokenResponse["error_description"] : "n/a")}");
        tokenResponse.Should().ContainKey("access_token");
        tokenResponse["access_token"]!.ToString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task CreatedClient_WrongSecret_ReturnsInvalidClient()
    {
        var clientId = $"c12-mgmt-wrong-{Guid.NewGuid():N}";
        const string clientSecret = "RealSecret-12345";

        var createExchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.ManageApps,
            new CreateApplicationRequest
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                ClientType = "confidential",
                DisplayName = "C12 wrong-secret negative",
                Permissions = ["ept:token", "gt:client_credentials"]
            },
            new Dictionary<string, object?> { ["operation"] = "create" });

        (createExchange.HasOut ? createExchange.Out!.Body : createExchange.In.Body)
            .Should().BeOfType<ApplicationResponse>();

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = "wrong-secret"
        });

        var response = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_client");
    }
}
