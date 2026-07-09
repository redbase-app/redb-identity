namespace redb.Identity.Core.Configuration;

/// <summary>
/// MFA-3 (WebAuthn / FIDO2 / Passkeys): Relying-Party configuration.
/// <para>
/// <b>Crypto-binding fields are explicit and fail-fast on misconfig.</b> RpId and Origins
/// participate in WebAuthn signature verification — once a credential is registered against
/// a given RpId, that credential is permanently bound to that RpId (the RpIdHash is part
/// of the signed authenticatorData). Changing RpId after deployment invalidates every
/// existing credential. To prevent that footgun, the validator (<see cref="Validate"/>)
/// requires RpId and at least one Origin to be explicitly set; null/empty defaults are
/// rejected with <see cref="InvalidOperationException"/> at startup. A wrong default would
/// cause silent breakage on the next domain rename.
/// </para>
/// <para>
/// <see cref="RpName"/> is cosmetic-only (shown in the OS authenticator UI as
/// "Sign in to {RpName}") and is auto-derived from the Identity issuer when unset.
/// </para>
/// </summary>
public sealed class IdentityWebAuthnOptions
{
    /// <summary>
    /// Master switch. When <c>false</c> (default) WebAuthn registration/assertion routes are
    /// not exposed and the WebAuthn challenge store is not required to be registered.
    /// When <c>true</c>, <see cref="Validate"/> is invoked at startup and will throw if
    /// <see cref="RpId"/> / <see cref="Origins"/> are unset.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// WebAuthn Relying Party ID — typically the registrable domain or a subdomain of it
    /// (e.g. <c>auth.example.com</c> or just <c>example.com</c>). Must NOT include scheme,
    /// port, or path. The browser will only release a credential to an RP whose origin's
    /// effective domain equals this value or is a registrable suffix.
    /// <para>
    /// <b>Required.</b> No default — must be set explicitly because changing it after
    /// credentials are registered breaks all of them.
    /// </para>
    /// </summary>
    public string? RpId { get; set; }

    /// <summary>
    /// Display name shown in the OS authenticator's prompt ("Sign in to {RpName} on
    /// auth.example.com"). Cosmetic only, not part of the cryptographic binding.
    /// Auto-derives from <see cref="RedbIdentityOptions.Issuer"/>'s host if null.
    /// </summary>
    public string? RpName { get; set; }

    /// <summary>
    /// Allowed origins for WebAuthn ceremonies, including scheme and port for non-default
    /// ports (e.g. <c>https://auth.example.com</c>, <c>https://auth.example.com:8443</c>).
    /// The browser includes the origin in <c>clientDataJSON</c>; the server rejects any
    /// origin not listed here. Multiple origins are valid for multi-app SSO scenarios where
    /// several apps share a single registrable domain.
    /// <para>
    /// <b>Required: must contain at least one origin.</b>
    /// </para>
    /// </summary>
    public List<string> Origins { get; set; } = new();

    /// <summary>
    /// Browser-side ceremony timeout in milliseconds. Authenticator will cancel after this
    /// elapses without user interaction. Default: 60 000 (60s) — WebAuthn-spec recommended
    /// for cross-platform / sync-passkey ceremonies. Server-side challenge TTL
    /// (<see cref="ChallengeTtlSeconds"/>) is independent.
    /// </summary>
    public int TimeoutMs { get; set; } = 60_000;

    /// <summary>
    /// Server-side TTL of issued challenges, in seconds. Must be ≥ TimeoutMs/1000 to give
    /// the browser ceremony enough time. Default: 300 (5 min) — matches OTP TTL and aligns
    /// with the encrypted setup-token / mfa_state TTL in <c>MfaStateProtector</c>.
    /// Consumed-challenge markers (<see cref="Models.WebAuthnConsumedChallengeProps"/>) are
    /// retained until this point past completion to anchor anti-replay.
    /// </summary>
    public int ChallengeTtlSeconds { get; set; } = 300;

    /// <summary>
    /// User-verification requirement: <c>required</c> | <c>preferred</c> | <c>discouraged</c>.
    /// <list type="bullet">
    ///   <item><description><c>required</c> = AAL2-strict; PIN/biometric every time. Breaks
    ///   older U2F-only authenticators (Yubikey 4 / Neo without FIPS firmware).</description></item>
    ///   <item><description><c>preferred</c> = AAL2 with graceful downgrade for legacy keys
    ///   (default). NIST AAL2 satisfied for credentials registered with UV; per-credential
    ///   <see cref="Models.WebAuthnCredential.UserVerified"/> ratchet (registered-with-UV →
    ///   must-assert-with-UV) blocks downgrade attacks.</description></item>
    ///   <item><description><c>discouraged</c> = single-factor (do NOT use for MFA).</description></item>
    /// </list>
    /// Default: <c>preferred</c>.
    /// </summary>
    public string UserVerification { get; set; } = "preferred";

    /// <summary>
    /// Attestation conveyance preference: <c>none</c> | <c>indirect</c> | <c>direct</c> |
    /// <c>enterprise</c>. <c>none</c> is recommended for passkey/MFA scenarios because
    /// sync-passkeys (iCloud Keychain, Google Password Manager) never produce attestation
    /// chains and would break under <c>direct</c>. Use <c>direct</c> only when AAL3 / FIDO L2
    /// certification is in scope (typically gov / regulated industries) — and have an
    /// AaguidBlocklist or MDS in place to act on the data. Default: <c>none</c>.
    /// </summary>
    public string Attestation { get; set; } = "none";

    /// <summary>
    /// Whether to fetch the FIDO Metadata Service (MDS3) on startup for AAGUID lookups
    /// (vendor name / icon / certification status / revocation list). Disabled by default
    /// — MDS requires HTTPS reachability of <c>https://mds3.fidoalliance.org/</c> and a
    /// JWT chain validation up to GlobalSign root, which is unsuitable for air-gapped /
    /// on-prem deployments. When false, <see cref="AaguidBlocklist"/> is the only AAGUID
    /// gating. v1.0 default: false (MFA AAL2 satisfied without MDS).
    /// </summary>
    public bool UseFidoMetadataService { get; set; }

    /// <summary>
    /// Manual list of banned authenticator AAGUIDs (16-byte GUIDs in the canonical
    /// <c>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</c> form). A registration request whose
    /// attested AAGUID matches an entry is rejected with <c>aaguid_blocked</c>. Useful for
    /// known-bad models (compromised supply-chain runs, recalled hardware) without bringing
    /// up MDS infra. Null/empty disables blocklist enforcement.
    /// </summary>
    public List<string>? AaguidBlocklist { get; set; }

    /// <summary>
    /// Interval between automatic cleanup of expired
    /// <see cref="Models.WebAuthnConsumedChallengeProps"/> rows. Set to
    /// <see cref="TimeSpan.Zero"/> or <see cref="Timeout.InfiniteTimeSpan"/> to disable.
    /// Default: 1 hour. Clustered — runs on the route-leader node only.
    /// </summary>
    public TimeSpan ChallengeCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if required fields are unset or invalid.
    /// Called from <c>RedbIdentityServiceExtensions.AddRedbIdentity</c> after
    /// <c>Configure&lt;IdentityWebAuthnOptions&gt;</c> binds the appsettings section, so a
    /// misconfigured deployment fails on startup rather than at first registration request.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(RpId))
            throw new InvalidOperationException(
                "IdentityWebAuthnOptions.RpId is required (e.g. \"auth.example.com\"). " +
                "Note: changing RpId after credentials are registered invalidates them — choose carefully.");

        if (RpId.Contains("://", StringComparison.Ordinal) || RpId.Contains('/', StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"IdentityWebAuthnOptions.RpId must be a bare host name without scheme/path, got '{RpId}'.");

        if (Origins is null || Origins.Count == 0)
            throw new InvalidOperationException(
                "IdentityWebAuthnOptions.Origins is required and must contain at least one https:// origin " +
                "(e.g. [\"https://auth.example.com\"]).");

        foreach (var origin in Origins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                || (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.Host == "localhost")))
            {
                throw new InvalidOperationException(
                    $"IdentityWebAuthnOptions.Origins entry '{origin}' must be an absolute https:// URL " +
                    "(http://localhost is also allowed for local dev).");
            }
        }

        if (TimeoutMs <= 0)
            throw new InvalidOperationException(
                $"IdentityWebAuthnOptions.TimeoutMs must be positive, got {TimeoutMs}.");

        if (ChallengeTtlSeconds <= 0 || ChallengeTtlSeconds * 1000 < TimeoutMs)
            throw new InvalidOperationException(
                $"IdentityWebAuthnOptions.ChallengeTtlSeconds ({ChallengeTtlSeconds}) must be positive " +
                $"and ≥ TimeoutMs/1000 ({TimeoutMs / 1000}).");

        if (UserVerification is not ("required" or "preferred" or "discouraged"))
            throw new InvalidOperationException(
                $"IdentityWebAuthnOptions.UserVerification must be one of required/preferred/discouraged, got '{UserVerification}'.");

        if (Attestation is not ("none" or "indirect" or "direct" or "enterprise"))
            throw new InvalidOperationException(
                $"IdentityWebAuthnOptions.Attestation must be one of none/indirect/direct/enterprise, got '{Attestation}'.");

        if (AaguidBlocklist is { Count: > 0 })
        {
            foreach (var entry in AaguidBlocklist)
            {
                if (!Guid.TryParse(entry, out _))
                    throw new InvalidOperationException(
                        $"IdentityWebAuthnOptions.AaguidBlocklist entry '{entry}' is not a valid GUID.");
            }
        }
    }
}
