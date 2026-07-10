using System.IO;
using System.Linq;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// W6-1: HTTPS by default in development. Pins the launch profile to a
/// configuration that includes an HTTPS endpoint, so a future "no need
/// for certs, just use http" edit does not silently downgrade the dev
/// loop and let cookie/CSRF defences regress to no-op.
/// </summary>
public class DevTlsContractTests
{
    private static string LaunchSettingsPath()
    {
        // Tests run from bin/Debug/netX/ — climb up to the Web project's Properties.
        var here = AppContext.BaseDirectory;
        var dir = new DirectoryInfo(here);
        while (dir is not null && dir.Name != "redb.Identity.Web.Tests")
            dir = dir.Parent;

        if (dir?.Parent?.Parent is null)
            throw new InvalidOperationException(
                $"Could not locate repo layout from {here}");

        // tests/redb.Identity.Web.Tests/ -> tests/ -> redb.Identity/ -> src/redb.Identity.Web/Properties/launchSettings.json
        var root = dir.Parent.Parent;
        return Path.Combine(
            root.FullName, "src", "redb.Identity.Web", "Properties", "launchSettings.json");
    }

    [Fact]
    public void LaunchSettings_HasHttpsProfile_BoundToDevPort()
    {
        var path = LaunchSettingsPath();
        File.Exists(path).Should().BeTrue($"launchSettings.json missing at {path}");

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var profiles = doc.RootElement.GetProperty("profiles");

        profiles.TryGetProperty("https", out var https).Should().BeTrue(
            "An 'https' launch profile MUST exist so `dotnet run` and IDE F5 bring up the BFF " +
            "with TLS by default (W6-1).");

        var applicationUrl = https.GetProperty("applicationUrl").GetString() ?? string.Empty;
        applicationUrl.Should().Contain("https://",
            "applicationUrl MUST include an https:// binding (got '{0}').", applicationUrl);

        var env = https.GetProperty("environmentVariables").GetProperty("ASPNETCORE_ENVIRONMENT").GetString();
        env.Should().Be("Development", "the https profile is the dev profile");
    }

    [Fact]
    public void DevelopmentAppSettings_RequiresHttpsMetadata()
    {
        var path = Path.Combine(
            Path.GetDirectoryName(LaunchSettingsPath())!, "..", "appsettings.Development.json");
        path = Path.GetFullPath(path);

        File.Exists(path).Should().BeTrue($"appsettings.Development.json missing at {path}");

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var identity = doc.RootElement.GetProperty("Identity");

        identity.GetProperty("Authority").GetString().Should().StartWith("https://",
            "BFF dev config must point at an https authority so OIDC discovery validates the TLS chain.");

        identity.GetProperty("RequireHttpsMetadata").GetBoolean().Should().BeTrue(
            "Setting RequireHttpsMetadata=false in committed dev config silently disables " +
            "metadata signature validation; require the developer to opt-in per-machine if needed.");
    }
}
