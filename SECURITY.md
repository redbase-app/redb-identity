# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.6.x   | :white_check_mark: |
| < 3.6   | :x: |

## Reporting a Vulnerability

redb.Identity is an OAuth 2.0 / OpenID Connect authorization server. A defect here can
compromise every application that trusts it, so please report privately rather than in a
public issue.

Two channels, either is fine:

1. **GitHub private advisory** (preferred) —
   [Report a vulnerability](https://github.com/redbase-app/redb-identity/security/advisories/new).
   Anyone with a GitHub account can file one; it stays private between you and the maintainer.
2. **Email** — **security@redbase.app**

Please include:

- Affected package(s) and version
- Description of the vulnerability
- Steps to reproduce, or a proof-of-concept request/response pair
- Potential impact assessment

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

**Do NOT** open a public GitHub issue for a security problem. Everything else — bugs,
questions, feature requests — belongs in the public tracker and is welcome from anyone.

## Scope

This policy covers the redb.Identity family:

- `redb.Identity.Core` (authorization server, token issuance, key management)
- `redb.Identity.Core.Module`, `redb.Identity.Contracts`
- `redb.Identity.Http`, `redb.Identity.Grpc`, `redb.Identity.Management`
- `redb.Identity.Client`, `redb.Identity.Web`
- `redb.Identity.DataProtection`, `redb.Identity.Ldap`
- `redb.Identity.Resource.Dpop`

Especially in scope: token issuance and validation, PKCE, redirect-URI handling, scope and
consent enforcement, refresh-token rotation and reuse detection, DPoP proof validation,
introspection and revocation, JWKS exposure and key rotation, MFA enrolment and recovery
codes, SCIM and Management API authorization, LDAP federation, session and cookie handling.

Out of scope: findings that require an already-compromised host or database, missing
hardening headers on the demo web UI, and rate-limit tuning of a deployment you control.

## Security Notes for Operators

### Signing keys across replicas

Signing keys live in the shared redb database when the persistent key store is enabled.
With more than one replica, enable it explicitly — the option defaults to `false`:

```csharp
services.Configure<RedbIdentityOptions>(o =>
{
    o.UsePropsSigningKeyStore = true;   // shared JWKS across replicas
    o.AllowEphemeralKeys      = false;  // never in production
});
```

Leaving `UsePropsSigningKeyStore = false` on a multi-replica deployment gives each replica
its own key set, so tokens issued by one replica fail validation at another. Verify by
hitting `/.well-known/jwks` on every replica and comparing the `kid` sets.

Key material is encrypted at rest with ASP.NET Core Data Protection. Configure a persistent,
shared Data Protection key ring for any deployment with more than one replica, otherwise the
keys become unreadable after a restart.

### Ephemeral keys

`AllowEphemeralKeys = true` generates a throwaway key pair per process. It exists for local
development only. A production start-up with ephemeral keys enabled is a misconfiguration.

### TLS

Run the authorization server behind TLS. OpenID Connect discovery, token endpoints and
cookies assume `https`; plain `http` is acceptable only on `localhost` during development.
See `HTTPS.md` for the local certificate setup.

### Client secrets and registration

Confidential clients must use a real secret or private-key JWT authentication. Public clients
must use PKCE with `S256`. Registered redirect URIs are matched exactly — do not add wildcard
or open-ended entries.

### Rate limiting

Token, authorization and MFA endpoints are throttled. Keep throttling enabled in production
and size it for your traffic rather than turning it off.
