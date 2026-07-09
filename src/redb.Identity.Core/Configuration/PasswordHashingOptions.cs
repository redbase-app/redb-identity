namespace redb.Identity.Core.Configuration;

/// <summary>
/// C12 — password hashing configuration.
/// <para>
/// <see cref="Algorithm"/> selects the <em>primary</em> algorithm used for new password hashes.
/// On successful verification of a legacy hash (different algorithm, or same algorithm with
/// weaker parameters than the current configuration), the login flow re-hashes the plaintext
/// and persists it — the standard OWASP upgrade-on-login pattern. See
/// <c>Security.MultiFormatPasswordHasher</c> + <c>Services.LoginService</c> for the
/// implementation.
/// </para>
/// </summary>
public sealed class PasswordHashingOptions
{
    /// <summary>
    /// Primary algorithm used for new hashes. Default: <see cref="PasswordHashAlgorithm.Argon2id"/>
    /// (OWASP 2023+ recommendation for password storage; memory-hard, GPU-resistant).
    /// </summary>
    public PasswordHashAlgorithm Algorithm { get; set; } = PasswordHashAlgorithm.Argon2id;

    /// <summary>Argon2id parameters (used when <see cref="Algorithm"/> = <see cref="PasswordHashAlgorithm.Argon2id"/>).</summary>
    public Argon2idHashOptions Argon2id { get; set; } = new();

    /// <summary>BCrypt parameters (used when <see cref="Algorithm"/> = <see cref="PasswordHashAlgorithm.Bcrypt"/>
    /// and for verifying legacy BCrypt hashes).</summary>
    public BcryptHashOptions Bcrypt { get; set; } = new();
}

/// <summary>Enumeration of supported primary password-hashing algorithms.</summary>
public enum PasswordHashAlgorithm
{
    /// <summary>Argon2id — OWASP 2023+ recommended primary.</summary>
    Argon2id,

    /// <summary>BCrypt — legacy-compatible fallback.</summary>
    Bcrypt,
}

/// <summary>
/// Argon2id parameters. Defaults match OWASP 2023 guidance for password storage:
/// m=64 MiB, t=3, p=4, salt=16 bytes, hash=32 bytes (≈50–150 ms per verify on a modern CPU).
/// Tune per deployment and measure with <c>identity.password.verify.duration</c> histogram.
/// </summary>
public sealed class Argon2idHashOptions
{
    /// <summary>Memory cost in KiB. Default: 65536 (64 MiB).</summary>
    public int MemoryKib { get; set; } = 65536;

    /// <summary>Iterations (time cost). Default: 3.</summary>
    public int Iterations { get; set; } = 3;

    /// <summary>Degree of parallelism (lanes). Default: 4.</summary>
    public int Parallelism { get; set; } = 4;

    /// <summary>Salt length in bytes. Default: 16 (128 bit).</summary>
    public int SaltBytes { get; set; } = 16;

    /// <summary>Hash length in bytes. Default: 32 (256 bit).</summary>
    public int HashBytes { get; set; } = 32;
}

/// <summary>
/// BCrypt parameters. Defaults match current <c>redb.Core.Security.BcryptPasswordHasher</c>.
/// </summary>
public sealed class BcryptHashOptions
{
    /// <summary>BCrypt work factor. Default: 12 (~250 ms per verify on a modern CPU).</summary>
    public int WorkFactor { get; set; } = 12;
}
