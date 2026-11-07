using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using redb.Identity.Core.Services;

namespace redb.Identity.Ldap;

/// <summary>
/// DI registration for LDAP external user provider and sync infrastructure.
/// </summary>
public static class LdapServiceExtensions
{
    /// <summary>
    /// Registers <see cref="LdapExternalUserProvider"/> as an <see cref="IExternalUserProvider"/>
    /// using options bound from an <see cref="IConfiguration"/> section.
    /// </summary>
    public static IServiceCollection AddRedbIdentityLdap(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var options = new LdapProviderOptions();
        configuration.Bind(options);
        options.NormalizeAfterBind();
        return services.AddRedbIdentityLdap(options);
    }

    /// <summary>
    /// Registers <see cref="LdapExternalUserProvider"/> as an <see cref="IExternalUserProvider"/>
    /// with explicit options. Supports multi-provider via keyed options.
    /// </summary>
    public static IServiceCollection AddRedbIdentityLdap(
        this IServiceCollection services,
        LdapProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        services.AddKeyedSingleton(options.ProviderName, options);
        services.AddSingleton<IExternalUserProvider>(sp =>
            new LdapExternalUserProvider(
                options,
                sp.GetRequiredService<ILogger<LdapExternalUserProvider>>()));
        return services;
    }

    /// <summary>
    /// Registers <see cref="LdapExternalUserProvider"/> as an <see cref="IExternalUserProvider"/>
    /// with a configuration callback.
    /// </summary>
    public static IServiceCollection AddRedbIdentityLdap(
        this IServiceCollection services,
        Action<LdapProviderOptions> configure)
    {
        var options = new LdapProviderOptions();
        configure(options);
        return services.AddRedbIdentityLdap(options);
    }

    /// <summary>
    /// Adds an LDAP connectivity health check that probes all registered LDAP providers.
    /// </summary>
    public static IHealthChecksBuilder AddRedbIdentityLdapCheck(
        this IHealthChecksBuilder builder,
        string name = "redb-identity-ldap",
        HealthStatus? failureStatus = HealthStatus.Degraded,
        IEnumerable<string>? tags = null)
    {
        return builder.Add(new HealthCheckRegistration(
            name,
            sp => new LdapHealthCheck(
                sp.GetServices<IExternalUserProvider>(),
                sp.GetRequiredService<ILogger<LdapHealthCheck>>()),
            failureStatus,
            tags));
    }

    /// <summary>
    /// Registers the LDAP sync infrastructure:
    /// <see cref="LdapSyncOptions"/>, <see cref="LdapSyncHandler"/>,
    /// and optionally <see cref="LdapGroupMapper"/>.
    /// The <see cref="LdapSyncRouteBuilder"/> must be registered separately
    /// via <c>AddRouteBuilder&lt;LdapSyncRouteBuilder&gt;()</c>.
    /// </summary>
    public static IServiceCollection AddRedbIdentityLdapSync(
        this IServiceCollection services,
        Action<LdapSyncOptions> configure)
    {
        var options = new LdapSyncOptions();
        configure(options);
        return services.AddRedbIdentityLdapSync(options);
    }

    /// <summary>
    /// Registers the LDAP sync infrastructure with explicit options.
    /// </summary>
    public static IServiceCollection AddRedbIdentityLdapSync(
        this IServiceCollection services,
        LdapSyncOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        services.AddSingleton(options);
        services.AddScoped<LdapSyncHandler>();

        if (options.SyncGroups)
        {
            services.AddSingleton(options.GroupMapperOptions);
            services.AddScoped<LdapGroupMapper>();
        }

        return services;
    }
}
