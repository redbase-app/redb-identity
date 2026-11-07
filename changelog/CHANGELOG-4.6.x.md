# redb.Identity changelog: 4.6.x

Releases of the 4.6 line, moved here unchanged from CHANGELOG.md, which keeps the latest released line only.
Newer releases: [CHANGELOG.md](../CHANGELOG.md).

## [4.6.2] — 2026-11-05

### Security

- **DPoP-bound access tokens now require a DPoP proof at `/connect/userinfo` and the management API.** A token bound
  to a DPoP key is accepted there only as `Authorization: DPoP <token>` with a fresh proof carrying `ath`; as Bearer
  or without a proof it gets 401. Advisory: [GHSA-vmj2-8phj-mfxf](https://github.com/redbase-app/redb-identity/security/advisories/GHSA-vmj2-8phj-mfxf). Packages: `redb.Identity.Core`, `redb.Identity.Http`. Upgrade: [UPGRADING.md](../UPGRADING.md#dpop-bound-access-tokens-at-userinfo-and-the-management-api).

## [4.6.1] — 2026-11-04

### Changed

- **Built on redb 4.6.1, redb.Route 4.6.1 and redb.Tsak 4.6.1.** The images and archives take the fixes of those
  releases; redb.Identity itself has no change. Nothing to do on your side.

## [4.6.0] — 2026-11-03

### Fixed

- **An authorization request sent as POST no longer loses its parameters at the login page.** When the user had no
  session yet, `POST /connect/authorize` sent the browser to the login page without the request, and after login the
  server answered "The mandatory 'client_id' parameter is missing". The login and consent pages now return to the same
  request, including `client_id` with `request_uri` for pushed requests. Nothing to change on the client side. Packages: `redb.Identity.Http`.
