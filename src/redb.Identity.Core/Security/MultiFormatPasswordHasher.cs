using System;
using redb.Core.Security;

namespace redb.Identity.Core.Security;

/// <summary>
/// C12: dispatching password hasher that produces new hashes with the configured <em>primary</em>
/// algorithm (Argon2id by default) while remaining able to verify and transparently migrate
/// legacy hashes (BCrypt, legacy SHA256+salt, and — via any <see cref="IPasswordHasher"/> fallback
/// supplied as <paramref name="legacyVerifier"/> — PBKDF2 or other formats).
/// <para>
/// On successful verification of a legacy hash, callers should check <see cref="NeedsRehash"/>
/// and, if true, re-hash the plaintext with <see cref="HashPassword"/> and persist the new hash.
/// This is the standard OWASP "upgrade-on-login" pattern.
/// </para>
/// </summary>
public sealed class MultiFormatPasswordHasher : IPasswordHasher
{
    private readonly Argon2idPasswordHasher _primary;
    private readonly BcryptPasswordHasher _bcrypt;
    private readonly IPasswordHasher? _legacyVerifier;

    /// <summary>
    /// Creates a multi-format hasher.
    /// </summary>
    /// <param name="primary">Primary hasher used for new hashes (typically Argon2id).</param>
    /// <param name="bcrypt">
    /// BCrypt hasher used to verify pre-existing <c>$2a$/$2b$/$2y$</c> hashes (also falls back to
    /// the legacy SHA256+salt format emitted by <see cref="SimplePasswordHasher"/> when the stored
    /// hash contains a ':' separator). Required because BCrypt covers the install-base of existing
    /// deployments prior to C12.
    /// </param>
    /// <param name="legacyVerifier">
    /// Optional additional verifier for other legacy formats (e.g. PBKDF2 if migrating from an
    /// ASP.NET Identity V3 store). Consulted only when the stored hash does not match any of the
    /// native formats (Argon2id, BCrypt, legacy SHA256+salt).
    /// </param>
    public MultiFormatPasswordHasher(
        Argon2idPasswordHasher primary,
        BcryptPasswordHasher bcrypt,
        IPasswordHasher? legacyVerifier = null)
    {
        _primary = primary ?? throw new ArgumentNullException(nameof(primary));
        _bcrypt = bcrypt ?? throw new ArgumentNullException(nameof(bcrypt));
        _legacyVerifier = legacyVerifier;
    }

    /// <inheritdoc />
    public string HashPassword(string password) => _primary.HashPassword(password);

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPassword)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
            return false;

        // Argon2id native format — primary path.
        if (hashedPassword.StartsWith(Argon2idPasswordHasher.Prefix, StringComparison.Ordinal))
            return _primary.VerifyPassword(password, hashedPassword);

        // BCrypt modular crypt format — $2a$ / $2b$ / $2y$.
        if (hashedPassword.StartsWith("$2", StringComparison.Ordinal))
            return _bcrypt.VerifyPassword(password, hashedPassword);

        // Legacy SHA256+salt (':' separator) — BcryptPasswordHasher handles this legacy path.
        if (hashedPassword.Contains(':'))
            return _bcrypt.VerifyPassword(password, hashedPassword);

        // External legacy (e.g. PBKDF2).
        return _legacyVerifier?.VerifyPassword(password, hashedPassword) ?? false;
    }

    /// <summary>
    /// Returns true when the stored hash is not produced by the primary algorithm at the
    /// current parameters (i.e. the password should be re-hashed after a successful verify).
    /// </summary>
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword)) return true;
        return _primary.NeedsRehash(hashedPassword);
    }
}
