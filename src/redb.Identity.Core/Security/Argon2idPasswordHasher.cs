using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Logging;
using redb.Core.Security;

namespace redb.Identity.Core.Security;

/// <summary>
/// C12: Argon2id password hasher — OWASP 2023+ recommended primary algorithm.
/// <para>
/// Encoded hash format (PHC string, compatible with libargon2 / other implementations):
/// <c>$argon2id$v=19$m={memoryKb},t={iterations},p={parallelism}$&lt;base64-salt&gt;$&lt;base64-hash&gt;</c>.
/// Base64 is unpadded (RFC 7693 §3.5) to match the de-facto PHC format.
/// </para>
/// <para>
/// Defaults: memory=65536 KiB (64 MiB), iterations=3, parallelism=4, salt=16 bytes, hash=32 bytes.
/// At these parameters a single verify takes ~50–150 ms on a modern desktop CPU.
/// </para>
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    /// <summary>PHC algorithm prefix for Argon2id hashes.</summary>
    public const string Prefix = "$argon2id$";

    private readonly int _memoryKib;
    private readonly int _iterations;
    private readonly int _parallelism;
    private readonly int _saltBytes;
    private readonly int _hashBytes;
    private readonly ILogger<Argon2idPasswordHasher>? _logger;

    /// <summary>Memory cost in KiB used for new hashes.</summary>
    public int MemoryKib => _memoryKib;

    /// <summary>Iterations (time cost) used for new hashes.</summary>
    public int Iterations => _iterations;

    /// <summary>Degree of parallelism (lanes) used for new hashes.</summary>
    public int Parallelism => _parallelism;

    /// <summary>
    /// Creates an Argon2id hasher with OWASP 2023 parameters by default.
    /// </summary>
    public Argon2idPasswordHasher(
        int memoryKib = 65536,
        int iterations = 3,
        int parallelism = 4,
        int saltBytes = 16,
        int hashBytes = 32,
        ILogger<Argon2idPasswordHasher>? logger = null)
    {
        if (memoryKib < 8) throw new ArgumentOutOfRangeException(nameof(memoryKib), "Argon2id memory must be ≥ 8 KiB.");
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (parallelism < 1) throw new ArgumentOutOfRangeException(nameof(parallelism));
        if (saltBytes < 8) throw new ArgumentOutOfRangeException(nameof(saltBytes), "Salt must be ≥ 8 bytes.");
        if (hashBytes < 16) throw new ArgumentOutOfRangeException(nameof(hashBytes), "Hash must be ≥ 16 bytes.");

        _memoryKib = memoryKib;
        _iterations = iterations;
        _parallelism = parallelism;
        _saltBytes = saltBytes;
        _hashBytes = hashBytes;
        _logger = logger;
    }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        var salt = RandomNumberGenerator.GetBytes(_saltBytes);
        var hash = Compute(Encoding.UTF8.GetBytes(password), salt, _memoryKib, _iterations, _parallelism, _hashBytes);

        var sb = new StringBuilder(96);
        sb.Append(Prefix);
        sb.Append("v=19$m=").Append(_memoryKib.ToString(CultureInfo.InvariantCulture));
        sb.Append(",t=").Append(_iterations.ToString(CultureInfo.InvariantCulture));
        sb.Append(",p=").Append(_parallelism.ToString(CultureInfo.InvariantCulture));
        sb.Append('$').Append(ToB64NoPad(salt));
        sb.Append('$').Append(ToB64NoPad(hash));
        return sb.ToString();
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPassword)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword)) return false;
        if (!TryParse(hashedPassword, out var p)) return false;

        try
        {
            var computed = Compute(Encoding.UTF8.GetBytes(password), p.Salt, p.MemoryKib, p.Iterations, p.Parallelism, p.Hash.Length);
            return CryptographicOperations.FixedTimeEquals(computed, p.Hash);
        }
        catch (Exception ex)
        {
            // Compute() can throw on native-library errors, OOM under aggressive m=, or
            // wildly out-of-range parameters that slipped past TryParse. Treat as auth
            // failure (don't leak details to the user) but make sure operators see it \u2014
            // a sustained run is an availability/operational signal, not just "wrong password".
            _logger?.LogWarning(ex,
                "Argon2idPasswordHasher: VerifyPassword failed during Compute (m={Memory}, t={Iter}, p={Par}).",
                p.MemoryKib, p.Iterations, p.Parallelism);
            return false;
        }
    }

    /// <summary>
    /// Returns true when the stored hash's parameters are weaker than the hasher's current settings
    /// (i.e. upgrade is desirable). Non-Argon2id hashes always return true.
    /// </summary>
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword)) return true;
        if (!hashedPassword.StartsWith(Prefix, StringComparison.Ordinal)) return true;
        if (!TryParse(hashedPassword, out var p)) return true;
        return p.MemoryKib < _memoryKib || p.Iterations < _iterations || p.Parallelism < _parallelism;
    }

    private static byte[] Compute(byte[] password, byte[] salt, int memoryKib, int iterations, int parallelism, int hashBytes)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            Iterations = iterations,
            MemorySize = memoryKib,
        };
        return argon2.GetBytes(hashBytes);
    }

    private readonly record struct Parsed(int MemoryKib, int Iterations, int Parallelism, byte[] Salt, byte[] Hash);

    private static bool TryParse(string encoded, out Parsed parsed)
    {
        parsed = default;
        // $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        if (!encoded.StartsWith(Prefix, StringComparison.Ordinal)) return false;
        var parts = encoded.Split('$');
        // ["", "argon2id", "v=19", "m=...,t=...,p=...", "salt", "hash"]
        if (parts.Length != 6) return false;
        if (parts[1] != "argon2id") return false;
        if (!parts[2].StartsWith("v=", StringComparison.Ordinal)) return false;

        int m = 0, t = 0, p = 0;
        foreach (var kv in parts[3].Split(','))
        {
            var eq = kv.IndexOf('=');
            if (eq <= 0) return false;
            var k = kv.AsSpan(0, eq);
            var v = kv.AsSpan(eq + 1);
            if (!int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return false;
            if (k.SequenceEqual("m".AsSpan())) m = n;
            else if (k.SequenceEqual("t".AsSpan())) t = n;
            else if (k.SequenceEqual("p".AsSpan())) p = n;
        }
        if (m < 8 || t < 1 || p < 1) return false;

        byte[] salt, hash;
        try
        {
            salt = FromB64NoPad(parts[4]);
            hash = FromB64NoPad(parts[5]);
        }
        catch
        {
            return false;
        }

        parsed = new Parsed(m, t, p, salt, hash);
        return true;
    }

    private static string ToB64NoPad(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=');

    private static byte[] FromB64NoPad(string s)
    {
        var pad = (4 - s.Length % 4) % 4;
        return Convert.FromBase64String(pad == 0 ? s : s + new string('=', pad));
    }
}
