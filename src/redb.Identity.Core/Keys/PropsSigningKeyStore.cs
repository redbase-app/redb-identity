using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Keys;

/// <summary>
/// PROPS-backed implementation of <see cref="ISigningKeyStore"/>. Singleton; resolves
/// <see cref="IRedbService"/> and <see cref="IDataProtectionProvider"/> through a fresh DI
/// scope (<see cref="IServiceScopeFactory"/>) per operation to avoid captive-scoped-into-
/// singleton traps (identical lifetime pattern to <c>RedbXmlRepository</c>, A1).
/// <para>
/// Private keys are stored as DataProtection-encrypted base64 PEM bytes with the purpose
/// string <c>redb.identity.signing-keys.v1</c>. The DataProtection key ring is itself
/// bootstrapped from PROPS (<c>RedbXmlRepository</c>), therefore <c>RedbXmlRepositoryInitListener</c>
/// MUST execute before <c>SigningKeyInitListener</c> in <c>InitRoute.main</c>.
/// </para>
/// </summary>
public sealed class PropsSigningKeyStore : ISigningKeyStore
{
    private const string ProtectorPurpose = "redb.identity.signing-keys.v1";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PropsSigningKeyStore> _logger;

    public PropsSigningKeyStore(
        IServiceScopeFactory scopeFactory,
        ILogger<PropsSigningKeyStore> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ImmutableArray<SigningKeyMaterial>> GetAllAsync(CancellationToken ct = default)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var protector = scope.ServiceProvider
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(ProtectorPurpose);

        // Server-side filter: only keys still inside their validity window. Expired
        // rotations stay in the table for audit but never enter the working set, so
        // we do not waste a DataProtection.Unprotect call on them. A fresh deployment
        // typically has 1–2 rows here per kind (active + grace overlap).
        var now = DateTimeOffset.UtcNow;
        var rows = await redb.Query<SigningKeyProps>()
            .Where(k => k.NotAfter > now)
            .OrderByDescendingRedb(o => o.DateCreate)
            .ToListAsync()
            .ConfigureAwait(false);
        var builder = ImmutableArray.CreateBuilder<SigningKeyMaterial>(rows.Count);
        foreach (var row in rows)
        {
            var p = row.Props;
            SecurityKey? key;
            try
            {
                var protectedBytes = Convert.FromBase64String(p.EncryptedPem);
                var pemBytes = protector.Unprotect(protectedBytes);
                key = ParsePem(pemBytes, p.Algorithm);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "redb.Identity: failed to decrypt signing key kid={Kid} kind={Kind}; skipping",
                    p.Kid, p.KeyKind);
                continue;
            }
            builder.Add(new SigningKeyMaterial(
                p.Kid, p.KeyKind, p.Algorithm, key,
                p.NotBefore, p.NotAfter, p.IsActive));
        }
        return builder.ToImmutable();
    }

    public async Task<ImmutableArray<SigningKeyMaterial>> ListAllIncludingRetiredAsync(CancellationToken ct = default)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var protector = scope.ServiceProvider
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(ProtectorPurpose);

        // List = every row, no NotAfter filter. The admin endpoint surfaces retired keys
        // for audit; the JWKS endpoint uses GetAllAsync so retired keys do not leak.
        var rows = await redb.Query<SigningKeyProps>()
            .OrderByDescendingRedb(o => o.DateCreate)
            .ToListAsync()
            .ConfigureAwait(false);
        var builder = ImmutableArray.CreateBuilder<SigningKeyMaterial>(rows.Count);
        foreach (var row in rows)
        {
            var p = row.Props;
            SecurityKey? key;
            try
            {
                var protectedBytes = Convert.FromBase64String(p.EncryptedPem);
                var pemBytes = protector.Unprotect(protectedBytes);
                key = ParsePem(pemBytes, p.Algorithm);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "redb.Identity: failed to decrypt signing key kid={Kid} kind={Kind} during list; skipping",
                    p.Kid, p.KeyKind);
                continue;
            }
            builder.Add(new SigningKeyMaterial(
                p.Kid, p.KeyKind, p.Algorithm, key,
                p.NotBefore, p.NotAfter, p.IsActive));
        }
        return builder.ToImmutable();
    }

    public async Task<SigningKeyMaterial> RotateAsync(string keyKind, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyKind);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var protector = scope.ServiceProvider
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(ProtectorPurpose);

        // 1. Demote every currently-active key of this kind. The keys stay in the JWKS
        //    until their own NotAfter passes — that's the entire point of rotation: a
        //    smooth handover so RPs that cached the JWKS continue to validate tokens
        //    signed under the old key. RetireAsync is the explicit "remove from JWKS now"
        //    step, called once the cache grace window has elapsed.
        var activeRows = await redb.Query<SigningKeyProps>()
            .Where(k => k.KeyKind == keyKind && k.IsActive)
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var row in activeRows)
        {
            row.Props.IsActive = false;
            await redb.SaveAsync(row).ConfigureAwait(false);
        }

        // 2. Mint the new active key.
        var (algorithm, pemBytes) = GenerateKey(keyKind);
        var kid = "k_" + Guid.NewGuid().ToString("N");
        var protectedPem = Convert.ToBase64String(protector.Protect(pemBytes));

        var now = DateTimeOffset.UtcNow;
        var obj = new RedbObject<SigningKeyProps>(new SigningKeyProps
        {
            Kid = kid,
            KeyKind = keyKind,
            Algorithm = algorithm,
            EncryptedPem = protectedPem,
            NotBefore = now,
            NotAfter = now.AddDays(90),
            IsActive = true,
        });
        obj.name = kid;
        await redb.SaveAsync(obj).ConfigureAwait(false);

        InvalidateOpenIddictOptionsCache(scope.ServiceProvider);

        _logger.LogDebug(
            "redb.Identity: rotated signing key kind={Kind} new_kid={Kid} demoted={Demoted} algorithm={Alg}",
            keyKind, kid, activeRows.Count, algorithm);

        var pemBytesForReturn = protector.Unprotect(Convert.FromBase64String(protectedPem));
        var material = new SigningKeyMaterial(
            kid, keyKind, algorithm,
            ParsePem(pemBytesForReturn, algorithm),
            now, now.AddDays(90), true);
        return material;
    }

    public async Task<bool> RetireAsync(string kid, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        // Identity stamps the row's `name` to the kid at creation time, so the
        // simple WHERE on Kid hits the same value either way.
        var row = await redb.Query<SigningKeyProps>()
            .Where(k => k.Kid == kid)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (row is null) return false;

        var now = DateTimeOffset.UtcNow;
        if (row.Props.NotAfter <= now)
        {
            // Already retired — idempotent no-op.
            return true;
        }
        row.Props.NotAfter = now;
        row.Props.IsActive = false;
        await redb.SaveAsync(row).ConfigureAwait(false);

        InvalidateOpenIddictOptionsCache(scope.ServiceProvider);

        _logger.LogDebug("redb.Identity: retired signing key kid={Kid} (NotAfter set to now)", kid);
        return true;
    }

    /// <summary>
    /// Batch 12 diagnostic mode: invalidates BOTH the server and validation
    /// IOptionsMonitor caches so the next options read re-runs every PostConfigure.
    /// </summary>
    private void InvalidateOpenIddictOptionsCache(IServiceProvider sp)
    {
        try
        {
            var serverCache = sp.GetService<IOptionsMonitorCache<OpenIddictServerOptions>>();
            serverCache?.TryRemove(Options.DefaultName);

            var validationCache = sp.GetService<IOptionsMonitorCache<OpenIddictValidationOptions>>();
            validationCache?.TryRemove(Options.DefaultName);

            _logger.LogDebug(
                "redb.Identity: OpenIddict options cache invalidated (server={Server}, validation={Validation})",
                serverCache is not null, validationCache is not null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "redb.Identity: cache invalidation failed");
        }
    }

    public async Task EnsureBootstrappedAsync(string keyKind, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyKind);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var protector = scope.ServiceProvider
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(ProtectorPurpose);

        var hasActive = await redb.Query<SigningKeyProps>()
            .Where(k => k.KeyKind == keyKind && k.IsActive)
            .AnyAsync()
            .ConfigureAwait(false);
        if (hasActive)
            return;

        var (algorithm, pemBytes) = GenerateKey(keyKind);
        var kid = "k_" + Guid.NewGuid().ToString("N");
        var protectedPem = Convert.ToBase64String(protector.Protect(pemBytes));

        var now = DateTimeOffset.UtcNow;
        var obj = new RedbObject<SigningKeyProps>(new SigningKeyProps
        {
            Kid = kid,
            KeyKind = keyKind,
            Algorithm = algorithm,
            EncryptedPem = protectedPem,
            NotBefore = now,
            NotAfter = now.AddDays(90),
            IsActive = true,
        });
        obj.name = kid;

        try
        {
            await redb.SaveAsync(obj).ConfigureAwait(false);
            _logger.LogInformation(
                "redb.Identity: bootstrapped signing key kind={Kind} kid={Kid} algorithm={Alg}",
                keyKind, kid, algorithm);
        }
        catch (Exception ex)
        {
            // Racy bootstrap: another replica may have written the first key concurrently.
            // Check-then-rethrow-if-nothing-there would be nice but we cannot distinguish
            // unique-violation cleanly without provider-specific plumbing; re-read and log.
            var collisionWinner = await redb.Query<SigningKeyProps>()
                .Where(k => k.KeyKind == keyKind && k.IsActive)
                .AnyAsync()
                .ConfigureAwait(false);
            if (collisionWinner)
            {
                _logger.LogInformation(ex,
                    "redb.Identity: bootstrap write collided with another replica (kind={Kind}); continuing with the winning key",
                    keyKind);
                return;
            }
            throw;
        }
    }

    private static (string Algorithm, byte[] PemBytes) GenerateKey(string keyKind)
    {
        if (string.Equals(keyKind, "signing", StringComparison.OrdinalIgnoreCase))
        {
            using var rsa = RSA.Create(2048);
            var pem = rsa.ExportRSAPrivateKeyPem();
            return ("RS256", Encoding.UTF8.GetBytes(pem));
        }
        if (string.Equals(keyKind, "encryption", StringComparison.OrdinalIgnoreCase))
        {
            using var rsa = RSA.Create(2048);
            var pem = rsa.ExportRSAPrivateKeyPem();
            return ("RSA-OAEP", Encoding.UTF8.GetBytes(pem));
        }
        throw new ArgumentOutOfRangeException(nameof(keyKind), keyKind,
            "Supported kinds are 'signing' and 'encryption'.");
    }

    private static SecurityKey ParsePem(byte[] pemBytes, string algorithm)
    {
        var pem = Encoding.UTF8.GetString(pemBytes);
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new RsaSecurityKey(rsa);
    }
}
