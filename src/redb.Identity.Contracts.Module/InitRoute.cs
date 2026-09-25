using redb.Route.Abstractions;

// Tsak resolves the {Module}.config.json file by InitRoute's namespace
// (TsakModuleRegistry.DiscoverModulesInAssembly). Keep this namespace aligned with the shipped config
// filename `redb.Identity.Contracts.Module.config.json`.
namespace redb.Identity.Contracts.Module;

/// <summary>
/// Deliberately empty Tsak module. This package exists for its <b>companion</b>, not its code:
/// <c>redb.Identity.Contracts.dll</c> — the DTO assembly whose types cross the <c>direct-vm://</c>
/// boundary between the Identity core and its facades — ships here and nowhere else.
/// <para>
/// Why a package of its own: companions load through <c>LoadedAssemblyTracker</c> into one
/// process-wide instance, but a package's hot-reload force-replaces its own companions. While the
/// contracts rode inside <c>Core.Module.tpkg</c>, reloading the core alone handed the new core a new
/// <c>Contracts</c> instance and left every facade holding the old one — the same CLR type in two
/// copies, and a typed body crossing the boundary quietly became <c>null</c> on the other side
/// (Tsak F-12). In its own package the contracts survive any single module's reload untouched.
/// </para>
/// <para>
/// The corollary is the deployment rule this design makes explicit: reloading <b>this</b> package
/// replaces the contracts instance, so it must be followed by reloading every module that uses them —
/// which a contract change requires semantically anyway, in any architecture.
/// </para>
/// </summary>
public static class InitRoute
{
    /// <summary>No routes, no components, no listeners — the payload is the companion DLL.</summary>
    public static IRouteContext main(IRouteContext context) => context;
}
