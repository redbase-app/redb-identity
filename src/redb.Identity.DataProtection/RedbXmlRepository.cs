using System.Collections.Immutable;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;

namespace redb.Identity.DataProtection;

/// <summary>
/// ASP.NET DataProtection XML key repository backed by redb PROPS storage.
/// Each key is stored as a <see cref="RedbObject{TProps}"/> of <see cref="DataProtectionKeyProps"/>.
/// <para>
/// <b>Snapshot pattern (A1):</b> <see cref="GetAllElements"/> returns an in-memory
/// <see cref="ImmutableArray{T}"/> snapshot — pure-sync, no I/O on the auth hot path
/// (called per <c>Protect/Unprotect</c>). The snapshot is seeded by a host-side init
/// listener (Core's <c>RedbXmlRepositoryInitListener</c>, or any facade-local equivalent)
/// in <c>OnContextStarting</c>, before any route processes its first exchange.
/// <see cref="StoreElement"/> is a rare write (key-ring rotation): it persists via a
/// fresh DI scope and updates the snapshot in-process via
/// <see cref="ImmutableInterlocked.Update{T,TArg}(ref ImmutableArray{T}, Func{ImmutableArray{T}, TArg, ImmutableArray{T}}, TArg)"/>.
/// </para>
/// <para>
/// <b>Lifetime:</b> registered as Singleton so it can be safely consumed by
/// <see cref="IXmlRepository"/> (resolved from the root container by <c>KeyManager</c>).
/// Persistence uses <see cref="IServiceScopeFactory"/> per call, so no Scoped
/// <see cref="IRedbService"/> is captured.
/// </para>
/// </summary>
public sealed class RedbXmlRepository : IXmlRepository
{
    private readonly IServiceScopeFactory _scopeFactory;
    private ImmutableArray<XElement> _snapshot = ImmutableArray<XElement>.Empty;

    public RedbXmlRepository(IServiceScopeFactory scopeFactory)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<XElement> GetAllElements() => _snapshot;

    /// <inheritdoc />
    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        // Bridge sync IXmlRepository contract to async redb. NOT on the auth hot path:
        // StoreElement is invoked only at key-ring rotation (rare), so the GetAwaiter().GetResult()
        // here cannot starve the thread pool the way a per-request bridge would.
        StoreElementAsync(element, friendlyName).GetAwaiter().GetResult();
    }

    private async Task StoreElementAsync(XElement element, string friendlyName)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var obj = new RedbObject<DataProtectionKeyProps>
        {
            name = friendlyName,
            Props = new DataProtectionKeyProps
            {
                FriendlyName = friendlyName,
                XmlContent = element.ToString(SaveOptions.DisableFormatting)
            }
        };
        await redb.SaveAsync(obj).ConfigureAwait(false);

        // Optimistic in-process snapshot update — visible to subsequent GetAllElements calls
        // without waiting for a refresh round-trip. Other cluster nodes pick this key up on
        // their next refresh / restart.
        ImmutableInterlocked.Update(ref _snapshot, (s, e) => s.Add(e), element);
    }

    /// <summary>
    /// Replaces the in-memory snapshot wholesale. Called by the host-side init listener
    /// during context startup (and by any future periodic refresh route).
    /// </summary>
    /// <remarks>
    /// Uses a plain assignment: <see cref="ImmutableArray{T}"/> is a struct wrapping a single
    /// reference field, and reference-sized writes are atomic on all supported .NET runtimes,
    /// so readers of <see cref="_snapshot"/> always observe either the old or new array in
    /// full (no torn read). <see cref="Interlocked.Exchange{T}(ref T, T)"/> cannot be used
    /// here because it is constrained to reference types and primitives and throws
    /// <see cref="NotSupportedException"/> for value-type generics like <c>ImmutableArray</c>.
    /// </remarks>
    public void ReplaceSnapshot(ImmutableArray<XElement> newSnapshot)
        => _snapshot = newSnapshot;
}
