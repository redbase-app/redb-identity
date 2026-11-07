# redb.Identity changelog: 4.5.x

Releases of the 4.5 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.5.1] — 2026-10-30

### Security

- **Audit targets receive the event and nothing of the request that raised it.** In 4.5.0 every target of
  `Identity:Audit:Targets` (Kafka, AMQP, a log endpoint, a consumer module) also got the request's headers: the client
  secret of a token request, `Authorization` with the bearer token, cookies, `redbHttp.*`; and a management read sent its
  answer (user, role or scope lists) instead of an event. Rotate those client secrets if a target stored or logged them. Packages: `redb.Identity.Core`.

### Fixed

- **A management call no longer repeats the previous call's audit event.** An in-process caller that sent one exchange
  to several management routes in a row (for example attach a scope to a role, then list the role's scopes) had the
  first operation's event raised again by every following call on that exchange. Each operation now raises only its own. Packages: `redb.Identity.Core`.

## [4.5.0] — 2026-10-29

### Breaking

- **A role's scopes reach a token only when the client asks for them.** They used to be added to every token of the
  user for any client, past the client's permissions, so an administrator's sign-in to any application gave it a
  token that administered Identity. Request the scope explicitly. Upgrade: [UPGRADING.md](../UPGRADING.md#role-scopes-only-when-the-client-asks-for-them). Packages: `redb.Identity.Core`. Upgrade: [UPGRADING.md](../UPGRADING.md#role-scopes-only-when-the-client-asks-for-them).

### Fixed

- **`Identity:Audit` takes effect when Identity runs as a Tsak module.** The targets the audit events are multicast
  to (Kafka, Elasticsearch, RabbitMQ, a log, a `direct-vm` route), the filter and the switches were ignored there, and
  events reached only the built-in audit table. They are now read from the context configuration. Packages: `redb.Identity.Core`, `redb.Identity.Core.Module`.
- **`Identity:SeedAdmin:Password` takes effect on a database shared with the Tsak dashboard.** In cluster mode the
  dashboard gives the empty `admin` its own default password first, and the configured one was then never applied.
  It now replaces a stored password that is still admin/admin; a password that was changed is left as it is. Packages: `redb.Identity.Core`.
- **The `TokenRevoked` audit event names the token's user.** A revocation at `/connect/revocation` or through the
  token management API now carries the user's id, like `TokensRevokedByUser` does, so a subscriber can act on that
  user alone. A client-credentials token has no user, and its event still carries none. Packages: `redb.Identity.Core`.
- **A group created with a name only works again.** For a member of a group without type and description, the user's
  group list failed with a `NullReferenceException`, and so did reading or updating that group. At sign-in this member
  got no group roles and was refused scopes and applications that require group membership. Nothing to do after
  upgrading. Packages: `redb.Identity.Core`.
- **`compose.managed.yml` and `compose.full.yml` no longer expose the Tsak management API.** It has no API keys in
  these images and answered on a published port 9090; it now listens on 127.0.0.1 inside the container, behind the
  dashboard, and the dashboard's password `TSAK_WEB_ADMIN_PASSWORD` is required instead of the image's admin/admin. Packages: `redb.Identity.Core.Module`.
- **Identity Web no longer warns on every start of the `full` image.** Its first revoked-sessions poll ran before
  the Identity host answered and was then retried only after a full poll interval. While the host is still starting,
  the poll now retries within seconds and logs that at information level; a refused secret still warns at once. Packages: `redb.Identity.Web`.
