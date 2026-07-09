using redb.Core.Models.Entities;

namespace redb.Identity.Core.Models;

/// <summary>
/// Hydrates [RedbIgnore] fields from root RedbObject fields after Load/Query.
/// ClientId, ScopeName live in <c>_objects.value_string</c> (indexed).
/// </summary>
internal static class RedbObjectHydration
{
    public static RedbObject<ApplicationProps> Hydrate(this RedbObject<ApplicationProps> obj)
    {
        obj.Props ??= new ApplicationProps();
        obj.Props.ClientId = obj.value_string ?? obj.Props.ClientId;
        return obj;
    }

    public static RedbObject<ScopeProps> Hydrate(this RedbObject<ScopeProps> obj)
    {
        obj.Props ??= new ScopeProps();
        obj.Props.ScopeName = obj.value_string ?? obj.Props.ScopeName;
        return obj;
    }

    public static RedbObject<ClaimScopeProps> Hydrate(this RedbObject<ClaimScopeProps> obj)
    {
        obj.Props ??= new ClaimScopeProps();
        obj.Props.ScopeName = obj.value_string ?? obj.Props.ScopeName;
        return obj;
    }

    public static RedbObject<ApplicationProps>? HydrateOrNull(this RedbObject<ApplicationProps>? obj)
        => obj is null ? null : obj.Hydrate();

    public static RedbObject<ScopeProps>? HydrateOrNull(this RedbObject<ScopeProps>? obj)
        => obj is null ? null : obj.Hydrate();

    public static List<RedbObject<T>> HydrateAll<T>(this List<RedbObject<T>> list, Action<RedbObject<T>> hydrate) where T : class, new()
    {
        foreach (var item in list) hydrate(item);
        return list;
    }
}
