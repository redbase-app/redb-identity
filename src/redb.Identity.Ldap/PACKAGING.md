# redb.Identity.Ldap — packaging notes

Status (2026-04-30): the LDAP integration is **shipped today as part of
`redb.Identity.Core.Module.tpkg`**. It is opt-in via configuration:

```jsonc
// redb.Identity.Core.Module.config.json (or any of the 5 layers above it)
"Identity": {
  "Ldap": {
    "Enabled": false,                  // master switch (default: false)
    "Providers": [
      {
        "ProviderName": "ldap",
        "Server": "ldap.example.com",
        "Port": 389,
        "BindDn": "cn=svc,dc=example,dc=com",
        "BindPassword": null,          // supply via Override layer / env / secret
        "UserBaseDn": "ou=users,dc=example,dc=com",
        "UserFilter": "(uid={0})",
        "Domains": [ "example.com" ],
        "AttributeMap": {
          "externalId":  "uid",
          "displayName": "cn",
          "email":       "mail"
        }
      }
    ],
    "Sync": {
      "Enabled": false                 // see "Sync route — known limitation" below
    }
  }
}
```

When `Identity.Ldap.Enabled = true`, `IdentityModuleHost` registers
`LdapExternalUserProvider` instances inside the **Identity child SP** so the
existing `LoginService` picks them up without any additional wiring.

`redb.Identity.Ldap.dll` (~150 KB plus its `redb.Route.Ldap` transitive) is
included unconditionally inside `redb.Identity.Core.Module.tpkg` even when the
feature is disabled. This is a deliberate trade-off — see "Why not a separate
.tpkg" below.

---

## Sync route — known limitation

`LdapSyncRouteBuilder` (the `Watch(...)` consumer that streams directory entries
into the local user store) is **not** activated by the in-Core integration. It
needs to be registered as an `IRouteBuilder` against the route context's
builder pipeline, which happens *outside* the Identity child SP. Until a
`AddRouteBuilder<LdapSyncRouteBuilder>` extension point is exposed on
`IRouteContext`, sync remains a feature you wire up by hand in a custom host.

Two reasonable paths to lift the limitation, both small:

1. Expose `IdentityCoreRouteBuilder.AppendBuilder(IRouteBuilder)` and call it
   from `InitRoute` when `Identity:Ldap:Sync:Enabled = true`. Cheapest.
2. Add a `LdapSyncInitListener : IRouteLifecycleListener` to the Identity child
   SP that builds the sync route and hands it to `IRouteContext.RegisterRoute`
   on startup. Cleanest separation, but requires confirming that route
   registration on a started context is supported by Tsak.

---

## Why not a separate `redb.Identity.Ldap.Module.tpkg`?

It is technically possible — it would mirror the shape of
`redb.Identity.Core.Module` — but the integration cost is **not** in the .tpkg
plumbing; it is in the cross-module DI bridge.

`LdapExternalUserProvider` implements `IExternalUserProvider`, an SPI that the
Core's `LoginService` consumes by enumerating `IEnumerable<IExternalUserProvider>`
**from the Core child SP**. If LDAP lives in its own child SP, Core cannot see
it. The two ways to bridge the gap:

### Option A1 — child-SP extension point

Have `redb.Identity.Core.Module` expose a registration callback (something like
`IdentityCoreOptionsExtensionPoint.AddSink(Action<IServiceCollection>)`) that
external `.tpkg` modules can publish to before the Identity child SP is built.
The LDAP module would register its callback during its own init so that, when
Identity.Core.Module later builds its child SP, it finds the callback in the
host root SP and applies it.

- Pros: native DI, zero runtime overhead, Core code unchanged after the hook
  exists.
- Cons: introduces a load-order coupling between `.tpkg`s (LDAP must initialise
  before Identity.Core's `InitRoute` runs); breaks the "modules are
  independent" mental model.

### Option A2 — message bus mediation

Convert `IExternalUserProvider` from a synchronous SPI into a request/response
contract over `direct-vm://identity-external-providers`. Core publishes a
"resolve user" envelope, every external provider module subscribes, the first
non-null response wins (or a configured priority order). LDAP module owns the
consumer side end-to-end.

- Pros: zero DI coupling between modules; LDAP can be deployed, replaced, or
  removed without touching Identity; clean cluster story (provider can run on
  a dedicated worker).
- Cons: round-trip latency on every login; requires correlation IDs, timeouts,
  and a fallback policy when no provider responds; existing
  `IExternalUserProvider` test surface needs reshaping.

### Verdict

Either option is a real refactor — not a packaging exercise — and is justified
only when at least one of the following becomes true:

1. LDAP needs its own deploy/upgrade cadence independent of Core.
2. Multiple Identity instances share a single LDAP backend deployed once.
3. A second external provider (e.g. SCIM-pull, custom HR system) appears, and
   the sync layer between Identity and providers becomes a real component.

Until then the shipped Variant B (LDAP wired into Core.Module by flag) is the
right level of investment.

---

## File-level checklist for promoting to a standalone `.tpkg` (later)

1. Create `redb.Identity.Ldap.Module/redb.Identity.Ldap.Module.csproj` mirroring
   `redb.Identity.Core.Module`. Reference both `redb.Identity.Ldap` and
   `redb.Identity.Core` (for `RedbIdentityOptions` if needed).
2. Add `LdapModuleHost.Build(IRouteContext, LdapModuleOptions)` that builds a
   child SP with `LdapExternalUserProvider[]`, `LdapSyncHandler`, and
   `LdapHealthCheck`.
3. Add `InitRoute` (`AutoStart = true`) that calls `LdapModuleHost.Build` and
   registers a `ChildHostDisposeListener`.
4. Add `redb.Identity.Ldap.Module.config.json` with the `Identity.Ldap.*`
   schema documented above.
5. Pick A1 or A2 from above for the DI / SPI bridge to Identity.Core.
6. Update `pack-tpkg.ps1` to emit a third `.tpkg` and copy it to
   `redb.Tsak.Worker/Libs/`.
7. Remove the `Identity:Ldap` block from
   `redb.Identity.Core.Module.config.json` and the `ProjectReference` from
   `redb.Identity.Core.Module.csproj` to drop the ~150 KB unconditional
   payload.

The path is open; nothing in the current Variant B implementation forecloses
it. The only thing that would have to change in Core when migrating is the
removal of the LDAP-specific code path inside `IdentityModuleHost.Build`,
which is fenced behind `if (options.Ldap.Enabled)` and easy to lift.
