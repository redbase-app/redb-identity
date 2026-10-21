# redb.Identity changelog: 4.3.x

Releases of the 4.3 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.3.0] — 2026-10-14

> **Why the bump.** redb.Identity ships with the ecosystem: this release is built on **redb.Route 4.3.0**
> and **redb.Tsak 4.3.0** and carries their changes into an Identity host. It brings no redb.Identity
> source change of its own, and every package in the table above moves to 4.3.0 together.
>
> What the pinned bump means for a deployment:
>
> - **redb.Route 4.3.0 reworks error handling.** What a `RouteBuilder` declares applies to the routes it
>   defines, not to every route of the context; each route gets its own error scope; the context has a
>   dead letter channel. Identity's own routes are unaffected: the core's only `OnException` is declared on
>   the token route itself (`IdentityCoreRouteBuilder`), not on the builder. A module loaded into an
>   Identity host that keeps its handlers in a builder of its own, or in a handlers-only Route-XML file, is
>   affected: those handlers no longer reach the routes of another builder or file, and the module has to be
>   checked before upgrading.
> - **redb.Tsak 4.3.0 gives every route context its own Quartz scheduler** and adds `tsak-dlq:`. A clustered
>   installation upgrades with a full stop of every node, the rows of the old `TsakScheduler-{cluster}` job
>   store are no longer read, and removing them is an operator command described with that release.
