using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using redb.Route.Abstractions;

namespace redb.Identity.Grpc.Module;

/// <summary>
/// Binds the Tsak-merged context configuration into a strongly typed
/// <see cref="IdentityGrpcTransportOptions"/> for the gRPC facade.
/// </summary>
/// <remarks>
/// Mirrors <c>redb.Identity.Http.Module.IdentityHttpConfigBinder</c>: Tsak hands the merged 5-layer
/// config to the module as a nested <c>IDictionary&lt;string, object?&gt;</c> on
/// <see cref="IRouteContext"/>; we flatten it into <see cref="MemoryConfigurationSource"/> entries and
/// let <c>IConfiguration.Bind</c> hydrate the POCO, which gives free <see cref="Uri"/> / nested-object
/// handling.
/// <para>
/// Section name is <c>"IdentityTransport"</c> — the same root the HTTP facade reads, so one section in
/// <c>context.json</c> carries both facades: <c>IdentityTransport:Http:*</c> and
/// <c>IdentityTransport:Grpc:*</c>.
/// </para>
/// </remarks>
internal static class IdentityGrpcConfigBinder
{
    /// <summary>Top-level config section consumed by the transport facades.</summary>
    public const string SectionName = "IdentityTransport";

    /// <summary>
    /// Builds <see cref="IdentityGrpcTransportOptions"/> from the context's
    /// <c>"IdentityTransport"</c> property. Returns defaults when the property is missing, so the module
    /// runs in development without explicit configuration.
    /// </summary>
    public static IdentityGrpcTransportOptions Bind(IRouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = new IdentityGrpcTransportOptions();
        var raw = context.GetProperty<IDictionary<string, object?>>(SectionName);

        if (raw is not null && raw.Count > 0)
        {
            var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            Flatten(raw, prefix: string.Empty, sink: flat);

            new ConfigurationBuilder()
                .Add(new MemoryConfigurationSource { InitialData = flat })
                .Build()
                .Bind(options, opt => opt.BindNonPublicProperties = false);
        }

        BindSharedSection(context, options);
        return options;
    }

    /// <summary>
    /// Binds the shared <c>Identity:*</c> section (issuer + feature flags) on top of the module-local
    /// values. Same source Core and the HTTP facade read, so a toggle declared once is observed
    /// identically everywhere; a value set explicitly on <c>IdentityTransport:*</c> is overwritten when
    /// the shared section provides it, matching the HTTP binder's precedence.
    /// </summary>
    private static void BindSharedSection(IRouteContext context, IdentityGrpcTransportOptions options)
    {
        var identitySection = context.GetProperty<IDictionary<string, object?>>("Identity");
        if (identitySection is null || identitySection.Count == 0) return;

        var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(identitySection, prefix: string.Empty, sink: flat);

        var cfg = new ConfigurationBuilder()
            .Add(new MemoryConfigurationSource { InitialData = flat })
            .Build();

        // Bind onto the existing instances so keys the shared section omits keep the module-local value.
        var features = cfg.GetSection("Features");
        if (features.Exists()) features.Bind(options.Features);

        var issuer = cfg["Issuer"];
        if (!string.IsNullOrWhiteSpace(issuer) && Uri.TryCreate(issuer, UriKind.Absolute, out var parsed))
            options.Issuer = parsed;
    }

    private static void Flatten(IDictionary<string, object?> source, string prefix, IDictionary<string, string?> sink)
    {
        foreach (var kvp in source)
        {
            // Metadata keys ("//" comment blocks) belong to Tsak, not to the options POCO.
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
