# redb.Identity.Grpc

A gRPC facade for redb.Identity: the **service-to-service** protocol surface (`Token`, `Introspect`,
`Revoke`, `UserInfo`, `Discovery`, `Jwks`) and the **management** surface (40 admin operations across
Users, Applications, Groups, Scopes and Tokens), each on its own port.

It is a transport, not a second implementation. Every call is translated and handed to the same
`direct-vm://identity-*` routes the HTTP facade uses, so both transports observe one issuer, one client
registry, one token store, one set of feature flags and one audit trail. Nothing about the protocol is
decided here.

```
gRPC client ──▶ redb.Identity.Grpc ──direct-vm://identity-*──▶ redb.Identity.Core
HTTP  client ──▶ redb.Identity.Http ──direct-vm://identity-*──▶       ↑ the same routes
```

## What is in scope, and what is not

| Operation | Address | RFC |
|---|---|---|
| `Token` | `/identity.v1.Identity/Token` | RFC 6749 §3.2 |
| `Introspect` | `/identity.v1.Identity/Introspect` | RFC 7662 |
| `Revoke` | `/identity.v1.Identity/Revoke` | RFC 7009 |
| `UserInfo` | `/identity.v1.Identity/UserInfo` | OIDC Core §5.3 |
| `Discovery` | `/identity.v1.Identity/Discovery` | OIDC Discovery 1.0 |
| `Jwks` | `/identity.v1.Identity/Jwks` | RFC 7517 |
| health probe | `/grpc.health.v1.Health/Check` | gRPC Health Checking Protocol |

**Browser flows stay on HTTP** — `authorize`, login, consent, MFA pages, device verification. They need a
browser, redirects and a cookie session; a gRPC channel has none of those. **DPoP stays on HTTP** too:
RFC 9449 binds its proof to an HTTP method and URL, so a DPoP proof presented over gRPC would be
unverifiable by construction. These are boundaries, not gaps — see `doc/gRPC/README.md`.

The **management surface** is here too, on a port of its own — see [below](#the-management-surface).
Self-service (`/me`, account registration, password recovery, MFA enrolment) is not, and deliberately: it
is an end-user flow, not admin tooling.

## Installing

The facade ships as its own Tsak module (`.tpkg`) with `ContextName: identity.grpc`, and it has **no
compile-time dependency on `redb.Identity.Core`** — it talks to Core over `direct-vm://` only. Deploy it
beside `redb.Identity.Core.Module` (its only declared dependency) and, if you serve browsers, beside
`redb.Identity.Http`.

```powershell
./scripts/pack-tpkg.ps1 -Module Grpc      # or -Module All
```

Hosting it yourself instead of under Tsak is two lines in a route context:

```csharp
var context = new RouteContext(serviceProvider, "identity.grpc");
context.AddComponent(new GrpcComponent());
context.AddRoutes(new GrpcFacadeRouteBuilder(Options.Create(transportOptions)));
await context.Start();
```

## Configuration

Settings live in the shared `context.json` under the `identity.grpc` context, in an
`IdentityTransport:Grpc:*` section that mirrors the HTTP facade's own section. Shared values — issuer,
feature flags — come from the `Identity:*` root that Core reads, so they are declared once.

```jsonc
"identity.grpc": {
  "IdentityTransport": {
    "Grpc": {
      "Host": "0.0.0.0",
      "PublicPort": 5011,
      "ManagementPort": null,
      "Ssl": false,
      "ClientCertificateMode": "NoCertificate",
      "AllowedClientThumbprints": null,
      "Compression": "None",
      "MaxMessageSize": 4194304,
      "Health": true,
      "EmitHttpCompatHeaders": true
    }
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `Host` | `0.0.0.0` | Bind address. |
| `PublicPort` | `5001` | The protocol surface. **Never share it with the HTTP facade**: gRPC requires HTTP/2 while the HTTP facade serves HTTP/1.1 + HTTP/2, and one listener has a single protocol set. The shared host throws on that conflict rather than failing later with a framing error. |
| `ManagementPort` | `null` | `null` = same as `PublicPort` (the single-node default). Split it in production: the protocol surface is called by every relying party, the management surface only by admin tooling — different consumers, different blast radius, firewalled separately. |
| `Ssl` | `false` | TLS. Requires `SslCertPath` (PFX) and usually `SslCertPassword`. |
| `ClientCertificateMode` | `NoCertificate` | mTLS: `NoCertificate`, `AllowCertificate`, `RequireCertificate`. |
| `AllowedClientThumbprints` | `null` | Comma-separated SHA-1 thumbprints. When set, a certificate whose thumbprint is not listed is rejected even if its chain validates. |
| `Compression` | `None` | Reply compression: `None` or `Gzip`. Inbound gzip is always accepted regardless of this setting. |
| `MaxMessageSize` | `4194304` | Bytes, both directions. Enforced after inflation, so a compression bomb cannot slip past it. |
| `Health` | `true` | Serve `grpc.health.v1.Health/Check` on every listening port. Unauthenticated and two bytes long. |
| `EmitHttpCompatHeaders` | `true` | Mirror the client address into `redbHttp.RemoteAddress`. **Leave this on** — see below. |

### Why `EmitHttpCompatHeaders` defaults to on

Core keys its per-IP throttle, its brute-force lockout and its device metadata on
`redbHttp.RemoteAddress`. Those checks **no-op when the header is absent** rather than failing loudly, so
turning this off does not disable a feature you can see — it silently stops protecting the gRPC port while
every test and dashboard stays green. Callers cannot forge the header: the transport drops inbound
metadata carrying a reserved prefix before the route sees it.

## Calling it

Generate stubs from `redb.Identity.Contracts/Protos/identity.v1.proto`. That file is the published
contract; it is deliberately not compiled into the Contracts assembly, which stays a dependency-free DTO
package.

```csharp
var channel = GrpcChannel.ForAddress("https://identity.internal:5001");
var identity = new Identity.IdentityClient(channel);

var token = await identity.TokenAsync(new TokenRequest
{
    GrantType    = "client_credentials",
    ClientId     = "reporting-service",
    ClientSecret = secret,
    Scope        = "identity:read",
});
```

Client authentication works either way: `client_id` / `client_secret` as message fields, or
`authorization: Basic …` as call metadata. Core reads both, so the facade adds no step of its own. The
same is true of the `UserInfo` bearer token — `authorization: Bearer …` metadata or the `access_token`
field.

### Message shape

Requests name what the RFCs name and carry a `map<string, string> additional` for everything else. That
map is not a shortcut: the wire form of these endpoints has always been form-encoded key/value, so
extension grants and vendor parameters belong in it.

Responses type what the RFCs fix and put the rest in a `google.protobuf.Struct` — `extra` on token and
introspection, `claims` on userinfo, `document` on discovery and JWKS. Userinfo claims and introspection
members are open sets by design, so typing them would be a lie. Nothing the server returns is dropped.

### Errors

A gRPC call either succeeds or carries a status. An OAuth error document arriving as a *successful* call
would be invisible to every generated client, so it does not:

| Cause | Status |
|---|---|
| `invalid_client`, `invalid_token` | `UNAUTHENTICATED` |
| `access_denied`, `unauthorized_client` | `PERMISSION_DENIED` |
| `server_error` | `INTERNAL` |
| `temporarily_unavailable` | `UNAVAILABLE` |
| any other OAuth error | `INVALID_ARGUMENT` |
| rate limited (429) | `RESOURCE_EXHAUSTED` |
| scope guard (403) | `PERMISSION_DENIED` |
| database outage (503) | `UNAVAILABLE` |

A status Core decided itself wins over the error string, because Core's own codes are not all in an RFC
table — a rate-limited answer carries `error = "rate_limited"`, which no table names.

**Read the trailers.** A non-OK gRPC reply discards its payload, so the machine-readable detail travels
there and nowhere else:

| Trailer | Contents |
|---|---|
| `error` | the OAuth error code, e.g. `invalid_client` |
| `error-description` | human-readable detail, also in the status message |
| `retry-after` | seconds to wait, on `RESOURCE_EXHAUSTED` |
| `x-correlation-id` | the id this call was traced under |

```csharp
try
{
    await identity.TokenAsync(request);
}
catch (RpcException ex) when (ex.StatusCode == StatusCode.ResourceExhausted)
{
    var wait = ex.Trailers.GetValue("retry-after");   // seconds
}
```

### Correlation ids and idempotency

Send `x-correlation-id` in metadata and it is honoured and echoed back in a trailer; send nothing and one
is derived from the ambient trace id. This applies to every operation on both surfaces.

`idempotency-key` is **not** universal, and it is worth knowing where the line falls. Core applies its
idempotency cache to the management surfaces — users, applications, groups, scopes, tokens and the rest of
the admin API — so a retried `Users/Create` returns the original record instead of failing as a duplicate.
The protocol operations (`Token`, `Introspect`, `Revoke`, `UserInfo`, `Discovery`, `Jwks`) have no
idempotency layer: sending the header there is harmless and does nothing. Each operation is tagged with
its own name, so two different operations sharing one key do not collide.

## The envelope fallback

The same six operations are reachable without the `.proto` at all, through the connector's generic
address. Send a `RedbMessage` whose payload is the JSON body and whose `operation` header names the
operation (`token`, `introspect`, `revoke`, `userinfo`, `discovery`, `jwks`):

```
/redb.route.grpc.RedbService/Process   +   metadata: operation: token
```

The reply is a `RedbMessage` whose payload is the JSON answer. An unknown operation is `UNIMPLEMENTED`
and the status message lists the ones that exist. One surface, two spellings — use the typed contract
unless carrying a `.proto` is genuinely inconvenient.

## The management surface

The admin API, for tooling rather than for relying parties. Forty operations across five services, on
`ManagementPort`, generated from
[identity.management.v1.proto](../redb.Identity.Contracts/Protos/identity.management.v1.proto).

| Service | Operations |
|---|---|
| `identity.management.v1.Users` | `List` `Search` `Get` `Create` `Update` `Delete` `ChangePassword` `AdminResetPassword` |
| `identity.management.v1.Applications` | `List` `Get` `Create` `Update` `RotateSecret` `Delete` |
| `identity.management.v1.Groups` | `List` `Search` `Get` `Create` `CreateChild` `Update` `Delete` `Move` `Tree` `Path` `Children` `ListMembers` `AddMember` `UpdateMember` `RemoveMember` `UserGroups` `IsMember` |
| `identity.management.v1.Scopes` | `List` `Get` `Create` `Update` `Delete` |
| `identity.management.v1.Tokens` | `List` `Revoke` `RevokeBySubject` `Prune` |

These dispatch to the same controllers the HTTP management API dispatches to — one package,
`redb.Identity.Management`, shared by both facades. The REST endpoint of the same name is therefore the
documentation for what a payload contains, and the two transports cannot drift apart on argument names or
validation.

### Payload shape

Requests carry named arguments; responses carry whatever the operation returned:

```protobuf
message ManagementRequest  { google.protobuf.Struct arguments = 1; }
message ManagementResponse { google.protobuf.Value  result    = 1; }
```

Argument names are the ones the REST route and query parameters use — `id`, `offset`, `count` — and an
operation whose REST form takes a request body puts that body's fields in `arguments` directly.

```csharp
var users = new Users.UsersClient(channel);

var page = await users.ListAsync(
    new ManagementRequest { Arguments = Struct.Parser.ParseJson("""{"offset":0,"count":25}""") },
    new Metadata { { "authorization", $"Bearer {token}" } });
```

The payloads are `Struct` and not typed messages on purpose. Forty operations today and 142 on the whole
admin surface, over an API that still grows: typing every request and response would make each new field a
contract change consumers must regenerate for. The **addresses** are the contract — named, stable, and
generated into real client stubs — while the payload stays open. Raw JSON would have been the other way to
keep it open, and it would have cost you the generated client.

### Authorization

Every call is authenticated with a bearer token and then checked against the granular scope table — the
same table in Core that the HTTP management API is checked against, so **the same token yields the same
verdict on both transports**. Read and write map to different scopes, and write implies read but never the
inverse.

| Outcome | Status |
|---|---|
| no token, or a token that does not validate | `UNAUTHENTICATED` |
| valid token without the scope for this surface | `PERMISSION_DENIED`, `insufficient_scope` in a trailer |
| the operation's own refusal (`not_found`, `duplicate`, `validation_error`, …) | `NOT_FOUND`, `ALREADY_EXISTS`, `INVALID_ARGUMENT`, … |

**Self-service is not here.** `/me`, account registration, password recovery and MFA enrolment are
end-user flows reached from a browser or an app session, not admin tooling. Putting them on an admin port
would widen that port's blast radius for a caller that does not exist.

### Splitting the ports in production

`ManagementPort` defaults to `null`, meaning "share `PublicPort`" — convenient for a single node, wrong for
production. Set it, and the admin addresses answer only there; the protocol port returns `UNIMPLEMENTED`
for them, which is what makes a firewall rule on the admin port worth writing.

```jsonc
"PublicPort": 5011,
"ManagementPort": 5012,
"Ssl": true,
"ClientCertificateMode": "RequireCertificate"
```

## TLS and mTLS

```jsonc
"Ssl": true,
"SslCertPath": "/etc/redb/identity-grpc.pfx",
"SslCertPassword": "…",
"ClientCertificateMode": "RequireCertificate",
"AllowedClientThumbprints": "9F2C…A1, 4B77…E0"
```

mTLS is off by default so deployments without a client-certificate PKI are not blocked. It is the
recommended setting for the management port in production. Thumbprint pinning is an addition to chain
validation, not a replacement: an unlisted certificate is rejected even when its chain is valid.

## Operating it

- **Health** — `grpc.health.v1.Health/Check` on every listening port. It answers «is *this* listener
  serving», which a probe on another port cannot show.
- **Route ids** — one method address is one route: `grpc-identity-token`, `grpc-identity-introspect`,
  `grpc-identity-revoke`, `grpc-identity-userinfo`, `grpc-identity-discovery`, `grpc-identity-jwks`,
  `grpc-identity-envelope`. Each has its own metrics and lifecycle and can be suspended individually
  through the control bus.
- **Discovery is not rewritten.** The document advertises the server's HTTP endpoints, because those are
  the real ones. Handing gRPC callers rewritten addresses would point them at endpoints that do not exist.

## Further reading

| Document | Contents |
|---|---|
| `doc/gRPC/README.md` | scope, boundaries, phase map |
| `doc/gRPC/ARCHITECTURE.md` | why a facade and not a second implementation; the trust model of `direct-vm://` |
| `doc/gRPC/ROADMAP.md` | phases and their order |
| `doc/gRPC/CHECKLIST.md` | verifiable state of each phase |
| `doc/gRPC/OPEN_QUESTIONS.md` | decisions taken and their reasoning |
| `redb.Identity.Contracts/Protos/identity.v1.proto` | the published contract |
| `C:\Work\yaml\grpc\README.md` | the interop fixture: an independent `@grpc/grpc-js` client generated from that contract |
