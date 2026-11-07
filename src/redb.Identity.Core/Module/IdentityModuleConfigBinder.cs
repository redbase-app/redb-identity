using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Core.Module;

/// <summary>
/// Binds the Tsak-merged context configuration (5-layer pipeline:
/// appsettings → context.json → {Module}.config.json → Override) into a strongly typed
/// <see cref="RedbIdentityOptions"/> instance.
/// </summary>
/// <remarks>
/// Tsak hands us configuration as a nested <c>IDictionary&lt;string, object?&gt;</c>
/// stored on <see cref="IRouteContext"/> via <c>SetProperty</c>. To reuse the existing
/// .NET <c>IConfiguration.Bind(...)</c> machinery (with all its convention parsing,
/// <c>TimeSpan</c> handling, list expansion, etc.) we flatten the dictionary into
/// <see cref="MemoryConfigurationSource"/> entries and rebuild a transient
/// <see cref="IConfiguration"/>.
/// <para>
/// Two property classes that <c>IConfiguration.Bind</c> cannot construct from strings —
/// <see cref="ReverseProxyOptions.KnownProxies"/> (<see cref="IPAddress"/>) and
/// <see cref="ReverseProxyOptions.KnownNetworks"/> (<see cref="IPNetwork"/>) — are
/// post-processed manually after the bind.
/// </para>
/// <para>
/// Cryptographic credentials (<see cref="RedbIdentityOptions.SigningCredentials"/> /
/// <see cref="RedbIdentityOptions.EncryptionCredentials"/>) are NOT loaded from JSON.
/// They are produced by the key-provisioning step that runs separately
/// (e.g. ephemeral fallback for dev, redb-backed RSA store for production).
/// </para>
/// </remarks>
internal static class IdentityModuleConfigBinder
{
    /// <summary>Top-level config section consumed by Identity.</summary>
    public const string SectionName = "Identity";

    /// <summary>
    /// Builds <see cref="RedbIdentityOptions"/> from <paramref name="context"/>'s
    /// <c>"Identity"</c> property. Returns defaults when the property is missing or
    /// empty so the module can run in development without explicit configuration.
    /// </summary>
    public static RedbIdentityOptions Bind(IRouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = new RedbIdentityOptions();
        if (Configuration(context) is not { } cfg)
            return options;

        cfg.Bind(options, opt => opt.BindNonPublicProperties = false);

        // IConfiguration.Bind merges arrays/lists by index instead of replacing them, so a
        // user-supplied list with fewer elements than the default leaves the tail of the
        // default visible. For a config-driven server that's the wrong default — operators
        // expect "set the list to exactly this". Re-bind list-shaped properties manually
        // when the operator provided one.
        ReplaceListIfPresent(cfg, "DynamicRegistrationAllowedGrantTypes",
            arr => options.DynamicRegistrationAllowedGrantTypes = arr);
        ReplaceListIfPresent(cfg, "DynamicRegistrationAllowedScopes",
            arr => options.DynamicRegistrationAllowedScopes = arr);

        var federationSection = cfg.GetSection("FederationProviders");
        if (federationSection.Exists())
        {
            var providers = federationSection.Get<List<FederationProviderConfig>>();
            if (providers is not null)
                options.FederationProviders = providers;
        }

        // Post-process types Bind cannot parse from strings.
        BindReverseProxyIpAddresses(cfg, options);

        return options;
    }

    /// <summary>Sub-section of <see cref="SectionName"/> read by <see cref="BindAudit"/>.</summary>
    public const string AuditSection = "Audit";

    /// <summary>
    /// Builds <see cref="IdentityAuditOptions"/> from <c>Identity:Audit</c> of
    /// <paramref name="context"/>: the master switch, the event filter, the relational sink and the
    /// external targets the events are multicast to. Defaults when the section is missing.
    /// <c>Targets</c> replaces the default list rather than merging by index.
    /// </summary>
    public static IdentityAuditOptions BindAudit(IRouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var audit = new IdentityAuditOptions();
        var section = Configuration(context)?.GetSection(AuditSection);
        if (section is null || !section.Exists())
            return audit;

        section.Bind(audit, opt => opt.BindNonPublicProperties = false);
        var targets = section.GetSection(nameof(IdentityAuditOptions.Targets));
        if (targets.Exists())
            audit.Targets = targets.Get<List<AuditTarget>>() ?? [];
        return audit;
    }

    // The context's "Identity" property flattened into IConfiguration key-value form
    // (Section:Key:Index syntax), so the standard IConfiguration.Bind reflection path can hydrate
    // the POCOs; null when the property is missing or empty.
    private static IConfiguration? Configuration(IRouteContext context)
    {
        var raw = context.GetProperty<IDictionary<string, object?>>(SectionName);
        if (raw is null || raw.Count == 0)
            return null;

        var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(raw, prefix: string.Empty, sink: flat);
        return new ConfigurationBuilder()
            .Add(new MemoryConfigurationSource { InitialData = flat })
            .Build();
    }

    private static void ReplaceListIfPresent(IConfiguration cfg, string key, Action<string[]> setter)
    {
        var section = cfg.GetSection(key);
        if (!section.Exists()) return;
        var arr = section.Get<string[]>();
        if (arr is not null)
            setter(arr);
    }

    private static void Flatten(IDictionary<string, object?> source, string prefix, IDictionary<string, string?> sink)
    {
        foreach (var (key, value) in source)
        {
            var path = string.IsNullOrEmpty(prefix) ? key : $"{prefix}:{key}";
            switch (value)
            {
                case null:
                    sink[path] = null;
                    break;
                case IDictionary<string, object?> nested:
                    Flatten(nested, path, sink);
                    break;
                case System.Collections.IEnumerable list when value is not string:
                {
                    var i = 0;
                    foreach (var item in list)
                    {
                        var itemPath = $"{path}:{i}";
                        if (item is IDictionary<string, object?> itemDict)
                            Flatten(itemDict, itemPath, sink);
                        else
                            sink[itemPath] = item?.ToString();
                        i++;
                    }
                    break;
                }
                default:
                    sink[path] = value.ToString();
                    break;
            }
        }
    }

    /// <summary>
    /// IConfiguration.Bind cannot construct <see cref="IPAddress"/> / <see cref="IPNetwork"/>
    /// from strings — parse them manually.
    /// </summary>
    private static void BindReverseProxyIpAddresses(IConfiguration cfg, RedbIdentityOptions options)
    {
        var proxies = cfg.GetSection("ReverseProxies:KnownProxies").Get<string[]>();
        if (proxies is { Length: > 0 })
        {
            options.ReverseProxies.KnownProxies.Clear();
            foreach (var p in proxies)
            {
                if (IPAddress.TryParse(p, out var ip))
                    options.ReverseProxies.KnownProxies.Add(ip);
            }
        }

        var nets = cfg.GetSection("ReverseProxies:KnownNetworks").Get<string[]>();
        if (nets is { Length: > 0 })
        {
            options.ReverseProxies.KnownNetworks.Clear();
            foreach (var n in nets)
            {
                if (IPNetwork.TryParse(n, out var net))
                    options.ReverseProxies.KnownNetworks.Add(net);
            }
        }
    }
}
