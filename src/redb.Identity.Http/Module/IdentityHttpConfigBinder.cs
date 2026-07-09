using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using redb.Identity.Contracts.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Http.Module;

/// <summary>
/// Binds the Tsak-merged context configuration into a strongly typed
/// <see cref="IdentityTransportOptions"/> instance for the HTTP facade.
/// </summary>
/// <remarks>
/// Mirrors <c>redb.Identity.Core.Module.IdentityModuleConfigBinder</c>: Tsak hands us
/// the merged 5-layer config as a nested <c>IDictionary&lt;string, object?&gt;</c>
/// stored on <see cref="IRouteContext"/> via <c>SetProperty</c>. We flatten it into
/// <see cref="MemoryConfigurationSource"/> entries and let <c>IConfiguration.Bind</c>
/// hydrate the POCO — gives us free <see cref="TimeSpan"/> / <see cref="Uri"/> /
/// nested-object handling.
/// <para>
/// The bound section name is <c>"IdentityTransport"</c>, matching the shape declared
/// in <c>redb.Identity.Http.config.json</c> (Layer 4).
/// </para>
/// </remarks>
internal static class IdentityHttpConfigBinder
{
    /// <summary>Top-level config section consumed by the HTTP facade.</summary>
    public const string SectionName = "IdentityTransport";

    /// <summary>
    /// Builds <see cref="IdentityTransportOptions"/> from <paramref name="context"/>'s
    /// <c>"IdentityTransport"</c> property. Returns defaults when the property is
    /// missing so the module can run in development without explicit configuration.
    /// </summary>
    public static IdentityTransportOptions Bind(IRouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = new IdentityTransportOptions();
        var raw = context.GetProperty<IDictionary<string, object?>>(SectionName);
        if (raw is null || raw.Count == 0)
            return options;

        var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(raw, prefix: string.Empty, sink: flat);

        var cfg = new ConfigurationBuilder()
            .Add(new MemoryConfigurationSource { InitialData = flat })
            .Build();

        cfg.Bind(options, opt => opt.BindNonPublicProperties = false);

        // Cross-module feature flags live in the shared `Identity:Features:*` section so a
        // single declaration in context.json drives both Core (DI / direct-vm gating) and
        // Http (route mounting). When operators override `IdentityTransport:Features:*`
        // explicitly, the latter wins (per-module override semantics).
        BindSharedFeatureFlags(context, options);

        // IConfiguration.Bind merges arrays/lists by index; replace lists wholesale
        // when the operator provided one (matches Core binder semantics).
        var federationSection = cfg.GetSection("FederationProviders");
        if (federationSection.Exists())
        {
            var providers = federationSection.Get<List<FederationProviderConfig>>();
            if (providers is not null)
                options.FederationProviders = providers;
        }

        return options;
    }

    /// <summary>
    /// Reads the shared <c>Identity:Features:*</c> section from the route-context
    /// properties and binds it onto <paramref name="options"/>'s
    /// <see cref="IdentityTransportOptions.Features"/>. The shared section is the
    /// authoritative source of feature toggles for both Core and Http; values set on
    /// <c>IdentityTransport:Features:*</c> (legacy / per-module override) are
    /// overwritten when the shared section provides them.
    /// </summary>
    private static void BindSharedFeatureFlags(IRouteContext context, IdentityTransportOptions options)
    {
        var identitySection = context.GetProperty<IDictionary<string, object?>>("Identity");
        if (identitySection is null
            || !identitySection.TryGetValue("Features", out var featuresObj)
            || featuresObj is not IDictionary<string, object?> featuresDict
            || featuresDict.Count == 0)
        {
            return;
        }

        var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(featuresDict, prefix: "Features", sink: flat);

        var sharedCfg = new ConfigurationBuilder()
            .Add(new MemoryConfigurationSource { InitialData = flat })
            .Build();

        // Bind directly onto the existing Features instance so per-module overrides set
        // earlier on the same object are preserved when the shared section omits a key.
        sharedCfg.GetSection("Features").Bind(options.Features);
    }

    private static void Flatten(IDictionary<string, object?> source, string prefix, IDictionary<string, string?> sink)
    {
        foreach (var kvp in source)
        {
            // Skip metadata keys ("//" comment blocks, ContextName, AutoStart) that
            // are consumed by Tsak itself and are not part of IdentityTransportOptions.
            if (kvp.Key.StartsWith("//", StringComparison.Ordinal)) continue;

            var key = prefix.Length == 0 ? kvp.Key : $"{prefix}:{kvp.Key}";
            switch (kvp.Value)
            {
                case null:
                    sink[key] = null;
                    break;
                case IDictionary<string, object?> nested:
                    Flatten(nested, key, sink);
                    break;
                case System.Collections.IEnumerable list when kvp.Value is not string:
                    var idx = 0;
                    foreach (var item in list)
                    {
                        var indexed = $"{key}:{idx}";
                        if (item is IDictionary<string, object?> nestedItem)
                            Flatten(nestedItem, indexed, sink);
                        else
                            sink[indexed] = item?.ToString();
                        idx++;
                    }
                    break;
                default:
                    sink[key] = kvp.Value.ToString();
                    break;
            }
        }
    }
}
