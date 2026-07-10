using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Hosts redb.Identity.Web in-process via WebApplicationFactory.
/// Overrides Identity:* config so OIDC discovery does NOT call out
/// to a real authority during smoke tests.
/// </summary>
public class WebHostFixture : WebApplicationFactory<Program>
{
    /// <summary>Authority that will fail discovery (loopback w/ closed port).</summary>
    public const string UnreachableAuthority = "http://127.0.0.1:1/";
    public const string UnreachableMetadata = "http://127.0.0.1:1/.well-known/openid-configuration";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:Authority"]            = UnreachableAuthority,
                ["Identity:MetadataAddress"]      = UnreachableMetadata,
                ["Identity:RequireHttpsMetadata"] = "false",
                ["Identity:ApiBaseUrl"]           = UnreachableAuthority,
                ["Identity:ClientId"]             = "identity-web",
                ["Identity:ClientSecret"]         = "test-secret",
                ["Identity:Scopes:0"]             = "openid",
                ["Identity:Scopes:1"]             = "profile",
                ["Identity:Scopes:2"]             = "identity:manage",
                // W6-0: backchannel service-account creds + slow poll (1h)
                // so RevokedSidsPollHostedService does not hit the unreachable
                // authority during tests.
                ["Identity:BackchannelClient:ClientId"]     = "test-backchannel",
                ["Identity:BackchannelClient:ClientSecret"] = "test-secret",
                ["Identity:BackchannelClient:Scopes:0"]     = "identity:manage",
                ["Identity:RevokedSids:PollInterval"]       = "01:00:00",
                ["Bootstrap:Enabled"]             = "false",
                ["Bootstrap:Endpoint"]            = "http://127.0.0.1:1/internal/bootstrap-admin",
                ["Bootstrap:Secret"]              = "",
            });
        });
    }
}
