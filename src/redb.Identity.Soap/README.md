# redb.Identity.Soap

A WS-Trust facade for redb.Identity: `Issue`, `Validate`, `Cancel` and `Renew` over SOAP, for callers
whose stack builds clients from a WSDL and speaks WS-Trust rather than OAuth.

It is a transport, not a second implementation. Every request is translated and handed to the same
`direct-vm://identity-*` routes the HTTP and gRPC facades use, so all three observe one issuer, one
client registry, one token store, one set of feature flags and one audit trail. Nothing about who may
have what is decided here.

```
WS-Trust client ──▶ redb.Identity.Soap ──direct-vm://identity-*──▶ redb.Identity.Core
gRPC     client ──▶ redb.Identity.Grpc ──direct-vm://identity-*──▶        ↑ the same routes
HTTP     client ──▶ redb.Identity.Http ──direct-vm://identity-*──▶
```

## One address, four operations

Unlike the gRPC facade, this one mounts a single route. That is WS-Trust's own shape: every operation
goes to one address and is told apart by the WS-Addressing `Action`, which is what generated clients
emit. The endpoint counter in a worker log therefore reads **1** for this module, not 4.

| Operation | Action suffix | Core route | RFC / spec |
|---|---|---|---|
| `Issue` | `/RST/Issue` | `identity-token` | WS-Trust 1.3 §4.1, RFC 6749 §4.4 |
| `Validate` | `/RST/Validate` | `identity-introspect` | WS-Trust 1.3 §7, RFC 7662 |
| `Cancel` | `/RST/Cancel` | `identity-revoke` | WS-Trust 1.3 §5, RFC 7009 |
| `Renew` | `/RST/Renew` | `identity-token` | WS-Trust 1.3 §6, RFC 6749 §6 |

A client that sends no `Action` is still served: `wst:RequestType` inside the body is read as the
fallback, because clients omitting the addressing header are common enough that refusing them would
mean refusing the audience this facade exists for.

### What is not here

Browser flows (`authorize`, consent, login) stay on HTTP because they need a browser, redirects and a
cookie session. DPoP stays on HTTP because RFC 9449 binds its proof to an HTTP method and URL. The
administrative surface stays on HTTP and gRPC: someone arriving for WS-Trust wants tokens, and
usually manages users somewhere else. WS-Federation is a separate protocol with its own plan.

## The token

The `RequestSecurityTokenResponse` carries our ordinary JWT as a `wsse:BinarySecurityToken`, declared
with the RFC 8693 JWT value type. No second token format enters the system, so introspection and
revocation work on it without a single change — it is literally the same object every other transport
issues. SAML assertions are deliberately not implemented; the reasoning, and the conditions under
which that would be revisited, are in `doc/SOAP/OPEN_QUESTIONS.md`.

## Refusals are faults

A refusal leaves as a `soap:Fault`, never as a successful response carrying an error document: a client
that is told the call succeeded has no reason to look inside it, and generated WS-Trust clients branch
on the fault code.

| Core's verdict | Fault |
|---|---|
| Caller not authenticated, or refused | `wst:FailedAuthentication` |
| Scope not granted | `wst:InvalidScope` |
| Malformed or unsupported request | `wst:InvalidRequest` |
| Rate limited, unavailable, our failure | `soap:Server` |

Which verdict applies is decided by the core, not here. The status the core stated outranks the OAuth
`error` string in the body — read from the string alone, a rate-limited answer would fall through to
"malformed request" and tell a caller to fix what is not broken instead of to wait. That reading lives
once, in `redb.Identity.Contracts/IdentityVerdict.cs`, shared with the gRPC facade.

## TLS is required

The facade **refuses to start** without TLS. This is stricter than the other facades, for a specific
reason rather than a cautious one: `UsernameToken` carries the client secret in clear text unless the
digest form is used, so an STS on plain HTTP publishes credentials to anyone on the path. A warning in
a log is read after they have already travelled.

`AllowPlaintext: true` is the single way out, for a connection already terminated by a trusted proxy.
It exists so an operator states that choice rather than stumbling into it.

mTLS is available through `ClientCertificateMode` with `AllowedClientThumbprints` for pinning — the
natural configuration for an STS in a closed contour, where callers are known partners. An
unrecognised mode value is refused at start rather than read as "no certificate": a typo must not turn
mTLS off on an endpoint whose operator believes it is on.

## Configuration

Lives in the shared `context.json` under `IdentityTransport:Soap`, the same root the other facades
read. Issuer and feature flags come from `Identity:*`, so a value declared once is observed identically
by the core and by every facade.

```jsonc
"identity.soap": {
  "IdentityTransport": {
    "Soap": {
      "Host": "0.0.0.0",
      "Port": 5021,
      "Path": "/sts",

      "Ssl": true,
      "SslCertPath": "/etc/certs/sts.pfx",
      // A secret. Supply through an L5 override rather than this file:
      //   Tsak__Contexts__identity.soap__Override__IdentityTransport__Soap__SslCertPassword=<value>
      "SslCertPassword": null,
      "AllowPlaintext": false,

      "ClientCertificateMode": "NoCertificate",
      "AllowedClientThumbprints": null,

      "Wsdl": true,
      "EmitHttpCompatHeaders": true
    }
  }
}
```

`EmitHttpCompatHeaders` mirrors the caller's address into `redbHttp.RemoteAddress`, which is what the
core's per-IP throttle and brute-force lockout key on. Leave it on: without it those protections do not
fail, they see no address and quietly do nothing.

## The WSDL

Served on `GET {Path}?wsdl`, with the `soap:address` rewritten to the URL it was fetched from, so a
generated client points back at the endpoint it was generated from. This is not decoration: the
audience for this facade builds clients with generators, and an STS that answers only POST is one a
WCF or CXF developer cannot start from.

## Packaging

Ships as a Tsak `.tpkg` with its own context, `identity.soap`, and zero compile-time references to
`redb.Identity.Core` — the two meet only over `direct-vm://`. Build it with
`scripts/pack-tpkg.ps1 -Module Soap`; the package drops into the worker's `modules\` folder alongside
`context.json`.
