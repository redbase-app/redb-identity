using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using redb.Identity.Ldap;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Variant B LDAP integration: reads the optional <c>Identity:Ldap</c> sub-section
/// from the Tsak-merged context configuration and produces a strongly typed
/// <see cref="LdapIntegrationConfig"/> snapshot consumed by <see cref="IdentityModuleHost"/>.
/// </summary>
/// <remarks>
/// Lives in <c>redb.Identity.Core.Module</c> (not in <c>redb.Identity.Core</c>) so the
/// LDAP types remain optional from Core's perspective: only this packaging shim takes
/// the dependency on <c>redb.Identity.Ldap</c>.
/// </remarks>
internal static class LdapIntegrationConfigBinder
{
    private const string IdentitySection = IdentityModuleConfigBinder.SectionName;
    private const string LdapKey = "Ldap";

    /// <summary>
    /// Returns <c>null</c> when no <c>Identity:Ldap</c> section is present, otherwise a
    /// hydrated <see cref="LdapIntegrationConfig"/>. The caller decides whether to act on
    /// <see cref="LdapIntegrationConfig.Enabled"/>.
    /// </summary>
    public static LdapIntegrationConfig? Bind(IRouteContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var identity = context.GetProperty<IDictionary<string, object?>>(IdentitySection);
        if (identity is null
            || !identity.TryGetValue(LdapKey, out var ldapRaw)
            || ldapRaw is not IDictionary<string, object?> ldapDict
            || ldapDict.Count == 0)
        {
            return null;
        }

        var flat = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Flatten(ldapDict, prefix: string.Empty, sink: flat);

        var cfg = new ConfigurationBuilder()
            .Add(new MemoryConfigurationSource { InitialData = flat })
            .Build();

        var result = new LdapIntegrationConfig();
        cfg.Bind(result, opt => opt.BindNonPublicProperties = false);

        // IConfiguration.Bind merges list elements by index; for "Providers" we want a
        // full replacement so an operator can shrink the list between deploys.
        var providersSection = cfg.GetSection("Providers");
        if (providersSection.Exists())
        {
            var providers = providersSection.Get<List<LdapProviderOptions>>();
            result.Providers = providers ?? new List<LdapProviderOptions>();
        }

        foreach (var p in result.Providers)
            p.NormalizeAfterBind();

        return result;
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
}

/// <summary>
/// In-memory snapshot of the <c>Identity:Ldap</c> configuration sub-section.
/// </summary>
internal sealed class LdapIntegrationConfig
{
    /// <summary>Master switch. When <c>false</c>, no LDAP services are registered.</summary>
    public bool Enabled { get; set; }

    /// <summary>List of LDAP providers to register as <c>IExternalUserProvider</c>.</summary>
    public List<LdapProviderOptions> Providers { get; set; } = new();
}
