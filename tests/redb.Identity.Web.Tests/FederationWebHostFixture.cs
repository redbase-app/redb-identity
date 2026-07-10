using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Extends <see cref="WebHostFixture"/> with a single published federation provider so
/// the BFF login page renders a federation button. The host's public-providers HTTP
/// endpoint is not reachable from the in-memory TestServer (it lives in the Host
/// process); we instead intercept the typed <c>IIdentityClient</c> HttpClient via a
/// <see cref="DelegatingHandler"/> and return a canned JSON payload for the
/// <c>/api/v1/identity/federation-providers/public</c> path.
/// </summary>
public sealed class FederationWebHostFixture : WebHostFixture
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureTestServices(services =>
        {
            services.AddTransient<PublicProvidersStubHandler>();

            // Typed HttpClient registered by AddIdentityClient uses the type-name as the
            // named-client key. AddHttpMessageHandler attaches our stub to the pipeline so
            // we intercept the /federation-providers/public request before it hits the
            // (unreachable) UnreachableAuthority.
            services.AddHttpClient(nameof(redb.Identity.Client.IIdentityClient))
                .AddHttpMessageHandler<PublicProvidersStubHandler>();
        });
    }

    private sealed class PublicProvidersStubHandler : DelegatingHandler
    {
        // Canonical canned payload — must match the contract shape (ProviderId/DisplayName/Kind/Priority).
        private const string CannedJson =
            "[{\"providerId\":\"test-google\",\"displayName\":\"Test Google\",\"kind\":\"oidc\",\"priority\":10}]";

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri is { } uri
                && uri.AbsolutePath.EndsWith("/api/v1/identity/federation-providers/public", StringComparison.Ordinal))
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(CannedJson, Encoding.UTF8, "application/json"),
                    RequestMessage = request,
                };
                return Task.FromResult(resp);
            }
            return base.SendAsync(request, cancellationToken);
        }
    }
}
