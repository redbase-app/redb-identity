using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Client;
using redb.Identity.Client.Auth;
using Xunit;

namespace redb.Identity.Client.Tests.Setup;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddIdentityClient_Registers_Typed_HttpClient()
    {
        var services = new ServiceCollection();
        services.AddIdentityClient(o =>
        {
            o.BaseUrl = new Uri("https://identity.test/");
            o.Timeout = TimeSpan.FromSeconds(7);
        });
        // Provide a default token provider so the typed-client construction does not fail when used.
        services.AddSingleton<IAccessTokenProvider, NullTokenProvider>();

        using var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IIdentityClient>();
        client.Should().BeOfType<IdentityClient>();
    }

    [Fact]
    public void AddIdentityClient_Configures_BaseAddress_And_Timeout()
    {
        var services = new ServiceCollection();
        services.AddIdentityClient(o =>
        {
            o.BaseUrl = new Uri("https://identity.example.com/");
            o.Timeout = TimeSpan.FromSeconds(11);
        });
        services.AddSingleton<IAccessTokenProvider, NullTokenProvider>();

        using var sp = services.BuildServiceProvider();
        var client = (IdentityClient)sp.GetRequiredService<IIdentityClient>();
        // Reach into the typed-client's HttpClient via the private field set in the ctor.
        var http = (HttpClient)typeof(IdentityClient)
            .GetField("_http", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(client)!;
        http.BaseAddress.Should().Be(new Uri("https://identity.example.com/"));
        http.Timeout.Should().Be(TimeSpan.FromSeconds(11));
    }

    [Fact]
    public void IdentityClientOptions_Has_Sensible_Defaults()
    {
        var opts = new IdentityClientOptions();
        opts.BaseUrl.Should().Be(new Uri("https://localhost/"));
        opts.Timeout.Should().Be(TimeSpan.FromSeconds(30));
        opts.Scopes.Should().ContainSingle().Which.Should().Be("identity.admin");
        opts.ClientId.Should().BeNull();
        opts.ClientSecret.Should().BeNull();
        opts.ScimBaseUrl.Should().BeNull();
    }

    private sealed class NullTokenProvider : IAccessTokenProvider
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken ct = default) => Task.FromResult<string?>(null);
    }
}
