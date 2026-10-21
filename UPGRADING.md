# Upgrading redb.Identity

What to check and change when moving to a new version. Each section lists the changes that need action;
[CHANGELOG.md](CHANGELOG.md) has the full list of what changed.

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
