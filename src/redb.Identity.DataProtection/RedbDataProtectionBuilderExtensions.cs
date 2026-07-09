using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace redb.Identity.DataProtection;

/// <summary>
/// DI helpers for persisting ASP.NET DataProtection XML keys in redb PROPS storage.
/// <para>
/// Lives in <c>redb.Identity.DataProtection</c> (Phase 9a) so that any Identity facade
/// (Core, Http, gRPC, …) can opt-in to the redb-backed key-ring without taking a
/// project-reference on Core. The key-ring snapshot is then visible across cold
/// starts and cluster nodes — required for cookie / session-ticket continuity.
/// </para>
/// </summary>
public static class RedbDataProtectionBuilderExtensions
{
    /// <summary>
    /// Persists ASP.NET DataProtection XML keys in redb.
    /// <para>Usage: <c>services.AddDataProtection().PersistKeysToRedb();</c></para>
    /// <para>
    /// The repository is registered as Singleton (KeyManager resolves
    /// <see cref="IXmlRepository"/> from the root container). Persistence opens a
    /// fresh <see cref="IServiceScopeFactory"/> scope per call to avoid capturing a
    /// Scoped <see cref="redb.Core.IRedbService"/> (A1 captive-dependency rule).
    /// </para>
    /// </summary>
    public static IDataProtectionBuilder PersistKeysToRedb(this IDataProtectionBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<RedbXmlRepository>();
        builder.Services.TryAddSingleton<IXmlRepository>(
            sp => sp.GetRequiredService<RedbXmlRepository>());
        return builder;
    }
}
