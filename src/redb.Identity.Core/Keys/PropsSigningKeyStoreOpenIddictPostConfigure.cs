using System.Collections.Immutable;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Keys;

/// <summary>
/// A3: post-configures <see cref="OpenIddictServerOptions"/> with the signing / encryption credentials
/// held by the <see cref="ISigningKeyStore"/>. Runs only when
/// <see cref="RedbIdentityOptions.UsePropsSigningKeyStore"/> is true.
/// <para>
/// **Re-runs on every options refresh.** <see cref="PropsSigningKeyStore.RotateAsync"/> and
/// <see cref="PropsSigningKeyStore.RetireAsync"/> invalidate the <see cref="IOptionsMonitorCache{TOptions}"/>
/// entry, so the next <c>IOptionsMonitor&lt;OpenIddictServerOptions&gt;.CurrentValue</c> read builds a fresh
/// options instance through the whole Configure → PostConfigure chain, and this method sees the store as it
/// is now. It is additive within a build: it inserts, deduplicated by kid, and never clears a list another
/// configurer filled.
/// </para>
/// <para>
/// **One set of trusted keys.** The keys offered here are the store's working set — every key whose
/// <c>NotBefore..NotAfter</c> window contains the present moment (<see cref="ISigningKeyStore.GetAllAsync"/>).
/// Rotation demotes a key and leaves its <c>NotAfter</c> alone, so it stays in this set and tokens it signed
/// keep validating until that date: that is the handover window. Retirement sets <c>NotAfter</c> to now, so
/// the key leaves this set on the next refresh, for minting and validation alike: trust in a retired key ends
/// at retirement. The validation parameters are then a projection of the credential lists — exactly what
/// OpenIddict's own post-configure writes — so the outcome does not depend on which post-configure runs
/// last, and a credential another configurer added is trusted for validation as well.
/// </para>
/// <para>
/// An earlier revision built a second, broader "validation pool" of every persisted key past
/// <c>NotBefore</c>, retired ones included, and wrote it into the validation parameters so that tokens under
/// retired keys would keep validating "during a grace window". A retired key's window ends at retirement, so
/// that pool held retired keys for as long as their rows existed. It never reached a token only because
/// OpenIddict's post-configure ran after this one and rebuilt the parameters from the credentials — an
/// accident of registration order this component may not rely on, and does not any more.
/// </para>
/// <para>
/// **Who mints.** OpenIddict's signing-credential selection picks the first algorithm-compatible entry from
/// <see cref="OpenIddictServerOptions.SigningCredentials"/>, and encryption the first encryption
/// credential. Among the store's keys the active one is placed first, so newly rotated keys win while
/// demoted keys remain behind them for validation. Relative to credentials another configurer added (the
/// operator's own keys), <see cref="RedbIdentityOptions.MintingKeySource"/> decides: <c>Store</c> puts the
/// store's keys first, <c>Configured</c> puts them after the configured ones. Both sets validate and are
/// published either way.
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

        // The working set: NotAfter > now is the store's own server-side filter; NotBefore <= now keeps a key
        // scheduled for the future out until its time. Retired keys (NotAfter = the moment of retirement)
        // are not in this set, and nothing below reaches for them.
        var now = DateTimeOffset.UtcNow;
        var inWindow = _store.GetAllAsync().GetAwaiter().GetResult()
            .Where(m => m.NotBefore <= now)
            .ToImmutableArray();

        if (!inWindow.Any(m => string.Equals(m.KeyKind, "signing", StringComparison.OrdinalIgnoreCase)))
        {
            _logger.LogWarning(
                "redb.Identity: PROPS signing-key store has no in-window signing key at OpenIddict post-configure time. " +
                "OpenIddict will reject token-mint requests. SigningKeyInitListener should mint a fresh one " +
                "on first context start; if you see this in steady state, every signing key has been retired " +
                "and rotate must be called before clients can authenticate.");
        }

        var existingSigningKids = new HashSet<string>(
            options.SigningCredentials.Select(c => c.Key?.KeyId ?? string.Empty),
            StringComparer.Ordinal);
        var existingEncryptionKids = new HashSet<string>(
            options.EncryptionCredentials.Select(c => c.Key?.KeyId ?? string.Empty),
            StringComparer.Ordinal);

        // Where the store's keys land in each list decides who mints: OpenIddict signs with the first
        // compatible signing credential and encrypts with the first encryption credential, while every
        // entry validates and is published. With credentials another configurer added (the operator's
        // SigningCredentials / EncryptionCredentials), MintingKeySource says which source comes first —
        // its absence with both sources present is refused at registration. With the store alone, the
        // store leads. Insert reverses order (the last inserted lands at the insertion point), so demoted
        // keys go in first, oldest first, and the active key last — it lands at the insertion point and
        // wins the minting pick among the store's keys.
        var storeLeads = _options.Value.MintingKeySource != MintingKeySource.Configured;
        var signingAt = storeLeads ? 0 : options.SigningCredentials.Count;
        var encryptionAt = storeLeads ? 0 : options.EncryptionCredentials.Count;

        var ordered = inWindow
            .OrderBy(m => m.IsActive)
            .ThenBy(m => m.NotBefore);

        foreach (var m in ordered)
        {
            if (string.Equals(m.KeyKind, "signing", StringComparison.OrdinalIgnoreCase))
            {
                if (existingSigningKids.Contains(m.Kid)) continue;
                options.SigningCredentials.Insert(signingAt, new SigningCredentials(m.SecurityKey, m.Algorithm)
                {
                    Key = { KeyId = m.Kid },
                });
                existingSigningKids.Add(m.Kid);
            }
            else if (string.Equals(m.KeyKind, "encryption", StringComparison.OrdinalIgnoreCase))
            {
                if (existingEncryptionKids.Contains(m.Kid)) continue;
                options.EncryptionCredentials.Insert(encryptionAt, new EncryptingCredentials(
                    m.SecurityKey, m.Algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)
                {
                    Key = { KeyId = m.Kid },
                });
                existingEncryptionKids.Add(m.Kid);
            }
        }

        // The validation parameters are the credentials, seen as keys. A deferred projection over the live
        // lists, not a copy: a credential a later configurer adds is trusted too, and there is no second list
        // that could drift from the first. OpenIddict's own post-configure writes these two lines as well;
        // writing them here makes the result the same whichever of the two runs last.
        options.TokenValidationParameters.IssuerSigningKeys = options.SigningCredentials.Select(c => c.Key);
        options.TokenValidationParameters.TokenDecryptionKeys = options.EncryptionCredentials.Select(c => c.Key);

        _logger.LogDebug(
            "redb.Identity: OpenIddict credentials reconciled from PROPS store ({Signing} signing, {Encryption} encryption, active_kid={ActiveKid})",
            options.SigningCredentials.Count, options.EncryptionCredentials.Count,
            inWindow.FirstOrDefault(x => x.IsActive && x.KeyKind == "signing")?.Kid ?? "(none)");
    }
}
