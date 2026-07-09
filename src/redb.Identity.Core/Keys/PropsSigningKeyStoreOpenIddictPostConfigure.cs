using System.Collections.Immutable;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Keys;

/// <summary>
/// A3: post-configures <see cref="OpenIddictServerOptions"/> by populating signing /
/// encryption credentials loaded from the PROPS <see cref="ISigningKeyStore"/>. Runs only
/// when <see cref="RedbIdentityOptions.UsePropsSigningKeyStore"/> is true.
/// <para>
/// **Re-runs on every options refresh.** Originally this PostConfigure was a one-shot
/// because OpenIddict 5.x consumed <c>IOptions&lt;OpenIddictServerOptions&gt;</c> (singleton
/// cache, never invalidated). Batch 12 (2026-06-18) makes <see cref="Keys.PropsSigningKeyStore.RotateAsync"/>
/// / <see cref="Keys.PropsSigningKeyStore.RetireAsync"/> invalidate the
/// <see cref="IOptionsMonitorCache{TOptions}"/> entry so the next
/// <c>IOptionsMonitor&lt;OpenIddictServerOptions&gt;.CurrentValue</c> read re-evaluates
/// the entire Configure → PostConfigure chain — that means this method runs again with
/// the current store snapshot. Idempotency is preserved by <c>Clear()</c>-ing the credential
/// lists at the top before re-populating.
/// </para>
/// <para>
/// **Active key ordering.** OpenIddict's signing-credential selection picks the first
/// algorithm-compatible entry from <see cref="OpenIddictServerOptions.SigningCredentials"/>.
/// Sorting <c>IsActive</c> first guarantees that newly-rotated keys win the selection
/// while previously-active (demoted) keys remain available for token validation
/// throughout the grace window.
/// </para>
/// </summary>
internal sealed class PropsSigningKeyStoreOpenIddictPostConfigure
    : IPostConfigureOptions<OpenIddictServerOptions>
{
    private readonly ISigningKeyStore _store;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<PropsSigningKeyStoreOpenIddictPostConfigure> _logger;

    public PropsSigningKeyStoreOpenIddictPostConfigure(
        ISigningKeyStore store,
        IOptions<RedbIdentityOptions> options,
        ILogger<PropsSigningKeyStoreOpenIddictPostConfigure> logger)
    {
        _store = store;
        _options = options;
        _logger = logger;
    }

    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        if (!_options.Value.UsePropsSigningKeyStore) return;

        // Two-tier key pull:
        //   • signingPool — keys still in their NotBefore..NotAfter window. These go
        //     into OpenIddict.SigningCredentials and ARE picked for MINTING new tokens.
        //     Critically: retired keys are excluded so OpenIddict never signs new
        //     tokens with a kid that JWKS will refuse to advertise.
        //   • validationPool — ALL persisted keys (incl. retired) past NotBefore. These
        //     go into TokenValidationParameters.IssuerSigningKeys so in-flight tokens
        //     signed under previously-active-then-retired kids still VALIDATE during
        //     the grace window.
        var all = _store.ListAllIncludingRetiredAsync().GetAwaiter().GetResult();
        var now = DateTimeOffset.UtcNow;
        var validationPool = all.Where(m => m.NotBefore <= now).ToImmutableArray();
        var materials = validationPool.Where(m => m.NotAfter > now).ToImmutableArray();

        if (materials.Length == 0)
        {
            _logger.LogWarning(
                "redb.Identity: PROPS signing-key store has no in-window keys at OpenIddict post-configure time. " +
                "OpenIddict will reject token-mint requests. SigningKeyInitListener should mint a fresh one " +
                "on first context start; if you see this in steady state, every signing key has been retired " +
                "and rotate must be called before clients can authenticate.");
            return;
        }

        // Dedupe-by-kid + Insert at index 0 so the currently-active key always wins
        // OpenIddict's "first algorithm-compatible credential" selection for minting,
        // without disrupting older entries that may still be needed for VALIDATION of
        // in-flight tokens. Batch 12: this is invoked on every rotate / retire via
        // IOptionsMonitorCache.TryRemove (see PropsSigningKeyStore.InvalidateOpenIddictOptionsCache),
        // so it must be idempotent and additive — never clear the list, never disturb
        // existing references that other PostConfigures may have set up.
        var existingSigningKids = new HashSet<string>(
            options.SigningCredentials.Select(c => c.Key?.KeyId ?? string.Empty),
            StringComparer.Ordinal);
        var existingEncryptionKids = new HashSet<string>(
            options.EncryptionCredentials.Select(c => c.Key?.KeyId ?? string.Empty),
            StringComparer.Ordinal);

        // IsActive desc + NotBefore desc so the latest active key ends up at index 0
        // after the Insert loop (Insert reverses order — last inserted is at 0).
        var ordered = materials
            .OrderBy(m => m.IsActive)            // false first — these get Inserted lower (i.e. end up at higher index)
            .ThenBy(m => m.NotBefore);           // older first

        foreach (var m in ordered)
        {
            if (string.Equals(m.KeyKind, "signing", StringComparison.OrdinalIgnoreCase))
            {
                if (existingSigningKids.Contains(m.Kid)) continue;
                options.SigningCredentials.Insert(0, new SigningCredentials(m.SecurityKey, m.Algorithm)
                {
                    Key = { KeyId = m.Kid },
                });
                existingSigningKids.Add(m.Kid);
            }
            else if (string.Equals(m.KeyKind, "encryption", StringComparison.OrdinalIgnoreCase))
            {
                if (existingEncryptionKids.Contains(m.Kid)) continue;
                options.EncryptionCredentials.Insert(0, new EncryptingCredentials(
                    m.SecurityKey, m.Algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)
                {
                    Key = { KeyId = m.Kid },
                });
                existingEncryptionKids.Add(m.Kid);
            }
        }

        // Validation pool — feeds TokenValidationParameters.IssuerSigningKeys with the
        // FULL persisted history (including retired) so in-flight tokens signed under
        // previously-active-then-retired kids still validate during the grace window.
        // This is broader than SigningCredentials on purpose (see split above).
        options.TokenValidationParameters.IssuerSigningKeys = validationPool
            .Where(m => string.Equals(m.KeyKind, "signing", StringComparison.OrdinalIgnoreCase))
            .Select(m => m.SecurityKey)
            .ToList();
        options.TokenValidationParameters.TokenDecryptionKeys = validationPool
            .Where(m => string.Equals(m.KeyKind, "encryption", StringComparison.OrdinalIgnoreCase))
            .Select(m => m.SecurityKey)
            .ToList();

        _logger.LogDebug(
            "redb.Identity: OpenIddict credentials reconciled from PROPS store ({Signing} signing, {Encryption} encryption, active_kid={ActiveKid})",
            options.SigningCredentials.Count, options.EncryptionCredentials.Count,
            materials.FirstOrDefault(x => x.IsActive && x.KeyKind == "signing")?.Kid ?? "(none)");
    }
}
