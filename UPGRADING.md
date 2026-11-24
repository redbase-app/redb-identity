# Upgrading redb.Identity

What to check and change when moving to a new version. Each section lists the changes that need action;
[CHANGELOG.md](CHANGELOG.md) has the full list of what changed.

## 4.7.5

### Idempotency records keep no secrets

An answer that carries a secret shown once is no longer kept in the `Idempotency-Key` cache: webhook create and
rotate-secret, client secret rotation, MFA enrollment and recovery codes. A repeat with the same key is not carried
out again and answers `{"replayed":true,"secretWithheld":true,...}` with the status of the first answer. A client that
lost the first answer rotates the secret again. Dynamic client registration (`/connect/register`) no longer takes part
in the cache: a repeated registration registers another client.

Records stored by an earlier version keep the full answer, secret included, and earlier versions never deleted
expired records. After the upgrade the cleanup (`identity-idempotency-cleanup`, hourly) deletes every expired
record at its first run. A record still inside its time to live (`Identity:Idempotency:Ttl`, 24 hours by default)
that was stored with a secret replays it to a repeat with its key until it expires, and goes at the next run after.

Action: none is required. To have the records of these operations gone at once, delete them right after the
upgrade; a repeat of such a request in the following 24 hours then runs the operation again. The same statements
work on PostgreSQL, SQL Server and SQLite (in `sqlcmd`, run `SET QUOTED_IDENTIFIER ON;` first):

```sql
DELETE FROM _values WHERE _id_object IN (
  SELECT o._id FROM _objects o JOIN _schemes s ON s._id = o._id_scheme
  WHERE s._name = 'identity.idempotency_record'
    AND (o._name LIKE 'idem:manage-webhooks:%' OR o._name LIKE 'idem:manage-apps:%'
         OR o._name LIKE 'idem:mfa-manage:%' OR o._name LIKE 'idem:dynamic-register:%'));
DELETE FROM _objects
WHERE _id_scheme = (SELECT _id FROM _schemes WHERE _name = 'identity.idempotency_record')
  AND (_name LIKE 'idem:manage-webhooks:%' OR _name LIKE 'idem:manage-apps:%'
       OR _name LIKE 'idem:mfa-manage:%' OR _name LIKE 'idem:dynamic-register:%');
```

Nothing else changes: the other records keep replaying whole.

## 4.7.4

### Dynamic client registration: check the initial access token

A `DynamicRegistrationInitialAccessToken` that is empty or whitespace now counts as not configured: registration
is open and an anonymous registrant is refused the administrative scopes. Decide which of the two you want and set
it explicitly. With the images, environment variables do it without rebuilding:

- registration off:

      Tsak__Contexts__identity.core__Override__Identity__Features__EnableDynamicRegistration=false
      Tsak__Contexts__identity.http__Override__IdentityTransport__Features__EnableDynamicRegistration=false

- registration only with a token the deployment issued (a long random value):

      Tsak__Contexts__identity.core__Override__Identity__DynamicRegistrationInitialAccessToken=<random value>

Then review the registered applications for `client_credentials` clients nobody created on purpose.

### Image defaults from 4.7.4

The images and archives start with dynamic client registration off. To turn it on, set both switches and give it an
initial access token (a long random value), so that registration is not open:

    Tsak__Contexts__identity.core__Override__Identity__Features__EnableDynamicRegistration=true
    Tsak__Contexts__identity.http__Override__IdentityTransport__Features__EnableDynamicRegistration=true
    Tsak__Contexts__identity.core__Override__Identity__DynamicRegistrationInitialAccessToken=<long random value>

A JAR `request_uri` is fetched only over https and not from private network addresses. For a client that hosts its
request objects over http or on a private address:

    Tsak__Contexts__identity.core__Override__Identity__Jar__RequestUriAllowPrivateNetworkTargets=true
    Tsak__Contexts__identity.core__Override__Identity__Jar__RequestUriRequireHttps=false

## 4.6.2

### DPoP-bound access tokens at userinfo and the management API

This applies only when DPoP is enabled (`Dpop.Enabled = true`; it is off by default). Security fix, see
[GHSA-vmj2-8phj-mfxf](https://github.com/redbase-app/redb-identity/security/advisories/GHSA-vmj2-8phj-mfxf).

An access token bound to a DPoP key (its `cnf` claim holds `jkt`, RFC 9449) is now accepted at `/connect/userinfo`
and at the management and self-service API (`/api/v1/identity/...`, SCIM) only when the request carries:

- `Authorization: DPoP <access token>`, not `Bearer`;
- a `DPoP` header with a fresh proof signed by the bound key, whose `htm` and `htu` match the request and whose
  `ath` is the base64url SHA-256 of the access token, inside the `Dpop.IatToleranceSeconds` window, never reused.

Otherwise the answer is 401 `invalid_token` with `WWW-Authenticate: DPoP error="invalid_token", ...`. An access
token without `jkt` sent under the `DPoP` scheme is refused the same way. Plain Bearer tokens and certificate-bound
tokens (`x5t#S256`) work as before.

What to do:

1. Clients that obtain DPoP-bound tokens and call userinfo or the management API: send the `DPoP` scheme and a
   proof with `ath` on every such call. Clients that already do this need no change.
2. The gRPC and SOAP management surfaces cannot carry a DPoP proof, so a DPoP-bound token is refused there. Use a
   Bearer token (a token request without a `DPoP` header) for those calls, or call the HTTP management API.
3. `Dpop.RequireNonce` still applies to the token endpoint only.

## 4.5.0

### Role scopes only when the client asks for them

A scope attached to a role is no longer added to the user's tokens on its own. A token carries the scopes the
client requested, which OpenIddict checks against the client's `scp:` permissions; for a scope that
`AdminScopeEntitlement` gates (`identity:*`, `scim`, and whatever `GatedScopes` lists) the user's roles then decide
whether it stays. The role is the entitlement, the request is still needed.

Up to 4.4.2 every scope of the user's roles went into every token of that user, for any client and without the
client's permission being checked. An administrator signing in to any application handed it a token with
`identity:manage` and Identity's own audience, which the management API accepted.

Who notices: a client that relied on receiving a role's scope without asking for it. Add the scope to the
client's request (`scope=` of the authorization or token request) and make sure the client has the `scp:`
permission for it. The Identity Web console, the `redb-identity-app` template and the Tsak dashboard are not
affected: the first two request their scopes explicitly, the dashboard does not sign in through Identity.
Tokens issued before the upgrade keep their scopes until they expire; a refresh issues the new set.

A scope that only a role should open, for example an application's administrative scope, must be listed in
`Identity:AdminScopeEntitlement:GatedScopes`; otherwise the client's permission alone decides, for every user.

## 4.4

### OpenIddict 7

redb.Identity runs on OpenIddict 7.7 (was 6.3), with Microsoft.Extensions and ASP.NET Core 10.0.13,
Microsoft.IdentityModel 8.23.0 and DataProtection 10.0.13 on every target framework.

**Existing sessions survive the upgrade.** Access and refresh tokens issued by 6.3 keep validating: their JWT `typ`
header is unchanged, and stored token rows keep their short type (`refresh_token`), which OpenIddict 7 maps on read.
New rows store the URI form (`urn:ietf:params:oauth:token-type:refresh_token`); the token management API filter
accepts either spelling and matches both. A tool of your own that reads the token store directly has to accept both.

**Token exchange (RFC 8693)** runs on OpenIddict's built-in grant. Subject, actor and requested token types stay
limited to access tokens. When the subject (or actor) token is bound to both audiences and a presenter, the calling
client must be one of them: a token minted for client A can no longer be exchanged by an unrelated client B. A
subject or actor token of a disabled or deleted user is rejected with `invalid_grant`. The response carries
`issued_token_type`. An `audience` parameter is validated by OpenIddict and rejected unless registered. Check that the
clients which exchange tokens are the ones the tokens were issued to.

### Client assertions (private_key_jwt, client_secret_jwt)

OpenIddict 7 implements the client assertion rules of draft-ietf-oauth-rfc7523bis, which close a vulnerability of
`private_key_jwt`, and offers no way back. A client that authenticates with a JWT assertion must now send:

- `typ` header `client-authentication+jwt` (a plain `JWT` is rejected with `invalid_client`, "The specified token
  is not of the expected type");
- `aud` equal to the issuer (`issuer` of the discovery document), for every endpoint: the token endpoint URL, or the
  URL of the introspection or revocation endpoint, is no longer accepted.

Clients built on OpenIddict 7 do this already. Update the others before upgrading the server; clients that use
`client_secret_basic` or `client_secret_post` are not affected.

### DPoP-bound access tokens at third-party resource servers

DPoP-bound access tokens carry `cnf.jkt` (RFC 9449). OpenIddict 7's own validation checks `cnf` and knows only the
certificate-bound form (`x5t#S256`, RFC 8705): it fails with an internal error (ID2196) on a `jkt`. Identity itself
handles this; a resource server of your own that validates Identity's tokens with OpenIddict.Validation 7 needs the
same treatment (set `DisableProofOfPossessionValidation` for tokens whose `cnf` holds only `jkt`, and check the DPoP
proof itself, for example with `redb.Identity.Resource.Dpop`).

### resource parameter

`resource` (RFC 8707) is validated on `/connect/authorize`, `/connect/par` and token exchange; OpenIddict 6 ignored
it. A `resource` must be an absolute URI without a fragment, must be listed in the `Resources` of at least one scope
(`invalid_target` otherwise), and the client needs the `rsrc:<resource>` permission. Before upgrading, list in the
scopes every resource your clients send, and grant those clients the matching `rsrc:` permission; a client that sends
no `resource` is not affected.

### DataProtection key ring

**What was wrong.** Up to 4.3 the server's DataProtection key ring was meant to live in redb
(`DataProtectionKeyProps`) but did not: the repository was registered in DI only, and ASP.NET Core ignored it and
kept the ring in the default directory of the process user (`/root/.aspnet/DataProtection-Keys` in the Docker
images, `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys` on Windows). Everything Identity protects with that ring, the
signing and encryption keys of tokens in redb, TOTP secrets, client secrets of federation providers, session and
federation state cookies, depended on that directory. A container recreated without it could not decrypt its
signing keys and the server did not start (`failed to decrypt signing key`, then
`At least one encryption key must be registered`). Each node of a cluster had a ring of its own.

**What 4.4 does.** The ring lives in redb. The first start of 4.4 on a database records the moment the ring moved
(redb scheme `identity.dp_key_import`). On every start, before the first request, Identity imports into redb the keys
of the old file ring that were created before that moment and that redb does not hold yet: the default directory
above, plus `Identity:DataProtection:ImportKeysFromPath` when the old ring was somewhere else. The log shows a warning
with the number of keys and the directory. Keys already in redb are skipped, so the next start imports nothing; the
files are left in place and are no longer read or written. Encrypted keys are copied as they are and stay encrypted.

The import reads only a ring that still exists when 4.4 starts. If the 4.3 ring lived only inside the container (no
volume on `/root/.aspnet/DataProtection-Keys`), copy it out before the container is replaced
(`docker cp <container>:/root/.aspnet/DataProtection-Keys ./dp-keys-4.3`), mount the copy into the 4.4 container and
point `Identity:DataProtection:ImportKeysFromPath` at it for the first start. After the move the Identity server needs
no file ring; the `managed` and `full` compose files keep a named volume `dp_keys` there for the Tsak worker and
dashboard. Keys of those programs present before the move are imported too and are unused; later ones are not.

**Clusters.** Nodes that each kept their own file ring each add theirs on their first start of 4.4 (their keys predate
the move): the ring in redb becomes the union, every node reads every node's data, and new keys are shared from then
on. Two nodes importing the same key at once leave two rows for it, which is handled (one key per id is loaded). Data
a node protected before 4.4 stays readable only if that node starts 4.4 with its old ring present.

**If a container was already recreated without the old ring.** The keys are gone and the data protected with them
cannot be decrypted. Recover as follows:

1. Stop the server. Delete the objects of the redb scheme `identity.signing_key`. On the next start Identity creates
   new signing and encryption keys. Every issued token becomes invalid: users sign in again, clients request new
   tokens. (With the server running, `POST /api/v1/identity/signing-keys/rotate` replaces keys, but a server that
   cannot decrypt any key does not start.)
2. Users with TOTP cannot pass the TOTP check: an administrator removes it with
   `DELETE /api/v1/identity/mfa/totp/{userId}` and the user enrols again. Recovery codes, WebAuthn and SMS or e-mail
   codes are not affected.
3. Enter the client secrets of federation providers again (management API, federation providers).
