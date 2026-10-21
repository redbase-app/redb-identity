using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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
    /// The key manager reads its repository from <see cref="KeyManagementOptions.XmlRepository"/>
    /// only; a repository merely registered in DI is ignored and the key ring falls back to the file
    /// system of the process user. So the repository is set on the options, as
    /// <c>PersistKeysToFileSystem</c> and <c>PersistKeysToDbContext</c> do. An XML encryptor set on
    /// the same options (<c>ProtectKeysWith*</c>) keeps working: the repository stores what it is
    /// given.
    /// </para>
    /// <para>
    /// The repository is a Singleton. Persistence opens a fresh <see cref="IServiceScopeFactory"/>
    /// scope per call to avoid capturing a Scoped <see cref="redb.Core.IRedbService"/>
    /// (A1 captive-dependency rule).
    /// </para>
    /// </summary>
    public static IDataProtectionBuilder PersistKeysToRedb(this IDataProtectionBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<RedbXmlRepository>();
        builder.Services.TryAddSingleton<IXmlRepository>(
            sp => sp.GetRequiredService<RedbXmlRepository>());
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<KeyManagementOptions>, RedbKeyManagementOptionsSetup>());
        return builder;
    }

    private sealed class RedbKeyManagementOptionsSetup : IConfigureOptions<KeyManagementOptions>
    {
        private readonly RedbXmlRepository _repository;

        public RedbKeyManagementOptionsSetup(RedbXmlRepository repository) => _repository = repository;

        public void Configure(KeyManagementOptions options) => options.XmlRepository = _repository;
    }
}
