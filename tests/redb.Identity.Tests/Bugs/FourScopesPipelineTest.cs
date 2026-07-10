using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Bypass the route's OnException handler and call the OpenIddict pipeline directly
/// to get the raw DbException stack trace.
/// </summary>
[Collection("ProductionBootstrap")]
public class FourScopesPipelineTest
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public FourScopesPipelineTest(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Theory]
    [InlineData("openid profile email", "3 scopes")]
    [InlineData("openid profile email phone", "4 scopes")]
    public async Task AuthCode_ViaPipeline(string scopes, string label)
    {
        _output.WriteLine($"Testing {label}: {scopes}");

        using var scope = _fx.ServiceProvider.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = scopes,
            ["code_challenge"] = "test-challenge-placeholder-that-is-at-least-43-chars-long-for-pkce",
            ["code_challenge_method"] = "S256"
        };

        var exchange = new TestExchange
        {
            In = new TestMessage { Body = body },
            Pattern = ExchangePattern.InOut
        };
        exchange.In.Headers["session_user_id"] = _fx.TestUserId;
        exchange.In.Headers["session_username"] = ProductionBootstrapFixture.TestUsername;
        exchange.Out = new TestMessage();

        try
        {
            await handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Authorization);

            var response = exchange.Out?.Body;
            _output.WriteLine($"Response type: {response?.GetType().Name}");
            if (response is IDictionary<string, object?> dict)
            {
                foreach (var kv in dict)
                    _output.WriteLine($"  {kv.Key} = {kv.Value?.ToString()?[..Math.Min(kv.Value?.ToString()?.Length ?? 0, 80)]}");
            }
            else
            {
                _output.WriteLine($"  Body: {response}");
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine("=== RAW EXCEPTION (no route masking) ===");
            var current = ex;
            int depth = 0;
            while (current != null)
            {
                _output.WriteLine($"--- Depth {depth} ---");
                _output.WriteLine($"Type: {current.GetType().FullName}");
                _output.WriteLine($"Message: {current.Message}");
                _output.WriteLine($"Stack:\n{current.StackTrace}");
                current = current.InnerException;
                depth++;
            }
            throw;
        }
    }
}
