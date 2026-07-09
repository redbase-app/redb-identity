using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Client.Auth;

namespace redb.Identity.Client;

/// <summary>
/// DI extensions for registering <see cref="IIdentityClient"/> and the optional
/// <see cref="ClientCredentialsAccessTokenProvider"/> (for CLI / server-to-server scenarios).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="IIdentityClient"/> as a typed <see cref="HttpClient"/>.
    /// Note: <see cref="IAccessTokenProvider"/> is NOT registered here — consumer must
    /// supply it (Web → HttpContext-based, CLI → <see cref="AddClientCredentialsTokenProvider"/>).
    /// </summary>
    public static IServiceCollection AddIdentityClient(
        this IServiceCollection services,
        Action<IdentityClientOptions> configure)
    {
        services.Configure(configure);
        services.AddTransient<BearerTokenHandler>();
        services.AddHttpClient<IIdentityClient, IdentityClient>((sp, http) =>
        {
            var opts = sp.GetRequiredService<IOptions<IdentityClientOptions>>().Value;
            http.BaseAddress = opts.BaseUrl;
            http.Timeout = opts.Timeout;
            http.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<BearerTokenHandler>();
        return services;
    }

    /// <summary>
    /// Register <see cref="ClientCredentialsAccessTokenProvider"/> as the
    /// <see cref="IAccessTokenProvider"/> implementation. Use for CLI / server-to-server.
    /// </summary>
    public static IServiceCollection AddClientCredentialsTokenProvider(this IServiceCollection services)
    {
        services.AddHttpClient<ClientCredentialsAccessTokenProvider>();
        services.AddSingleton<IAccessTokenProvider>(sp =>
            sp.GetRequiredService<ClientCredentialsAccessTokenProvider>());
        return services;
    }
}
