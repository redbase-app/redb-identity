namespace redb.Identity.Core.Configuration;

/// <summary>
/// Which key source signs and encrypts new tokens when both configured credentials
/// (<see cref="RedbIdentityOptions.SigningCredentials"/> / <see cref="RedbIdentityOptions.EncryptionCredentials"/>)
/// and the props signing-key store (<see cref="RedbIdentityOptions.UsePropsSigningKeyStore"/>) are present.
/// Both sources are trusted for validation and published in the JWKS either way; only the minting key differs.
/// </summary>
public enum MintingKeySource
{
    /// <summary>
    /// The configured credentials mint; the store's keys only validate. The state of a deployment moving its
    /// keys to an HSM or a certificate: tokens signed by the store keep validating until they expire.
    /// </summary>
    Configured,

    /// <summary>
    /// The store's active key mints; the configured credentials only validate. The state of a deployment
    /// moving off configured keys onto the store.
    /// </summary>
    Store,
}
