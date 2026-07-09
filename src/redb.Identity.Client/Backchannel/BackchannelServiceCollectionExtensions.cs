using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace redb.Identity.Client.Backchannel;

/// <summary>
/// DI extensions for the W6-0 backchannel client. Registers
/// <see cref="IBackchannelIdentityClient"/> as a typed HttpClient backed by a
/// dedicated <see cref="BackchannelTokenProvider"/> using <c>client_credentials</c>.
/// </summary>
public static class BackchannelServiceCollectionExtensions
{
    /// <summary>
    /// Register the W6-0 backchannel client (<see cref="IBackchannelIdentityClient"/>).
    /// Coexists with the regular user-context <c>IIdentityClient</c> registration; the
    /// two clients use separate <see cref="HttpClient"/> instances and separate
    /// <c>Authorization</c> header pipelines.
    /// </summary>
    public static IServiceCollection AddBackchannelIdentityClient(
        this IServiceCollection services,
        Action<BackchannelIdentityClientOptions> configure)
    {
        services.Configure(configure);

        // Token-acquisition HttpClient (no auth header — calls /connect/token directly).
        services.AddHttpClient<BackchannelTokenProvider>((sp, http) =>
        {
            var o = sp.GetRequiredService<IOptions<BackchannelIdentityClientOptions>>().Value;
            http.BaseAddress = o.BaseUrl;
            http.Timeout = o.Timeout;
        });

        services.AddTransient<BackchannelBearerHandler>();

        services.AddHttpClient<IBackchannelIdentityClient, BackchannelIdentityClient>((sp, http) =>
        {
            var o = sp.GetRequiredService<IOptions<BackchannelIdentityClientOptions>>().Value;
            http.BaseAddress = o.BaseUrl;
            http.Timeout = o.Timeout;
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<BackchannelBearerHandler>();

        return services;
    }
}
