using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Exceptions;
using redb.Identity.Core.Mfa;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Orchestrates MFA operations: delegates to <see cref="IMfaMethod"/> implementations,
/// manages PROPS persistence, lockout, recovery codes, and OTP challenge dispatch.
/// </summary>
public sealed partial class MfaService
{
    private readonly IRedbService _redb;
    private readonly IReadOnlyDictionary<string, IMfaMethod> _methods;
    private readonly IReadOnlyDictionary<string, IMfaDeliveryChannel> _channels;
    private readonly MfaStateProtector _stateProtector;
    private readonly MfaSetupTokenProtector _setupTokenProtector;
    private readonly RedbIdentityOptions _options;
    private readonly ILogger<MfaService> _logger;
    private readonly ILogger _securityLogger;
    private readonly RecoveryCodePepperProvider _pepperProvider;
    private readonly TimeProvider _timeProvider;
    private readonly IServerSideOtpStore? _otpStore;

    private readonly int _maxFailedAttempts = 5;
    private readonly TimeSpan _lockoutDuration = TimeSpan.FromMinutes(15);
    private readonly int _recoveryCodeCount = 10;

    /// <summary>Cap on RecentOtpTimestamps list size to bound storage (B6 sliding window).</summary>
    private const int RecentOtpTimestampsCap = 50;

    /// <summary>Sliding-window length for OTP rate limiting (B6).</summary>
    private static readonly TimeSpan OtpRateLimitWindow = TimeSpan.FromHours(1);

    public MfaService(
        IRedbService redb,
        IEnumerable<IMfaMethod> methods,
        IEnumerable<IMfaDeliveryChannel> channels,
        MfaStateProtector stateProtector,
        MfaSetupTokenProtector setupTokenProtector,
        IOptions<RedbIdentityOptions> options,
        RecoveryCodePepperProvider pepperProvider,
        ILogger<MfaService> logger,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        IServerSideOtpStore? otpStore = null)
    {
        _redb = redb;
        _methods = methods.ToDictionary(m => m.MethodId, StringComparer.OrdinalIgnoreCase);
        _channels = channels.ToDictionary(c => c.ChannelId, StringComparer.OrdinalIgnoreCase);
        _stateProtector = stateProtector;
        _setupTokenProtector = setupTokenProtector;
        _options = options.Value;
        _pepperProvider = pepperProvider;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _otpStore = otpStore;
        // E5: security-channel for lockouts, rejected-verify, rate-limits.
        _securityLogger = loggerFactory is not null
            ? Security.IdentitySecurityLog.CreateLogger(loggerFactory)
            : logger;
    }

    /// <summary>Whether the user has at least one confirmed MFA method.</summary>
    public async Task<bool> IsMfaEnabledAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { Enabled: true } props) return false;
        return props.TotpConfirmed || props.SmsConfirmed || props.EmailConfirmed;
    }

    /// <summary>Returns the list of confirmed MFA method IDs for the user.</summary>
    public async Task<string[]> GetEnabledMethodsAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { Enabled: true } props)
            return [];

        return CollectEnabledMethods(props);
    }

    /// <summary>
    /// Atomic accessor (B9 / BUG-4): returns both the enabled flag and the confirmed
    /// method list from a single <c>MfaProps</c> read, eliminating the TOCTOU window
    /// between the prior <see cref="IsMfaEnabledAsync"/> + <see cref="GetEnabledMethodsAsync"/>
    /// pair (each of which fetched the props independently).
    /// </summary>
    public async Task<(bool Enabled, string[] Methods)> LoadMfaStatusAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { Enabled: true } props)
            return (false, Array.Empty<string>());

        var methods = CollectEnabledMethods(props);
        // Enabled is true ONLY if at least one method is confirmed — matches the
        // semantics of IsMfaEnabledAsync (which checks TotpConfirmed||Sms||Email).
        return (methods.Length > 0, methods);
    }

    private static string[] CollectEnabledMethods(MfaProps props)
    {
        var result = new List<string>(3);
        if (props.TotpConfirmed) result.Add("totp");
        if (props.SmsConfirmed && !string.IsNullOrEmpty(props.SmsPhone)) result.Add("sms");
        if (props.EmailConfirmed && !string.IsNullOrEmpty(props.OtpEmail)) result.Add("email");
        return result.ToArray();
    }

    /// <summary>
    /// Initiates MFA setup for a method. Returns setup data (QR URI, masked destination, etc.)
    /// AND an opaque, encrypted setup token that the client must present back to
    /// <see cref="ConfirmSetupAsync"/>. <b>Does NOT mutate <see cref="MfaProps"/> or save anything
    /// to the database</b> — the candidate secret/destination lives only in the setup token until
    /// confirm. This eliminates the "two parallel setups race-overwrite the secret" bug (B5).
    /// </summary>
    /// <param name="destination">Phone/email for SMS/Email; ignored by TOTP.</param>
    public async Task<MfaSetupResult> SetupAsync(long userId, string methodId, string username, string? destination = null, CancellationToken ct = default)
    {
        var method = GetMethod(methodId);

        var initiation = await method.InitiateSetupAsync(username, destination, ct).ConfigureAwait(false);

        // If initiation reported an error (e.g. invalid phone) — return the client payload as-is,
        // do not issue a setup token and do not touch the database.
        if (initiation.ClientResult.Extra is not null
            && initiation.ClientResult.Extra.ContainsKey("error"))
        {
            return initiation.ClientResult;
        }

        var token = _setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = userId,
            MethodId = methodId,
            EncryptedSecret = initiation.EncryptedSecret,
            Destination = initiation.Destination,
            IssuedAt = _timeProvider.GetUtcNow(),
            Jti = Guid.NewGuid()
        });

        _logger.LogDebug("MFA setup token issued: userId={UserId}, method={Method}", userId, methodId);

        return initiation.ClientResult with { SetupToken = token };
    }

    /// <summary>
    /// Confirms MFA setup by verifying the first code against the candidate secret/destination
    /// carried inside <paramref name="setupToken"/>. The setup token is the opaque string returned
    /// by <see cref="SetupAsync"/>. Returns recovery codes (plain text, shown once) on success or
    /// <c>null</c> if the token is invalid/expired or the code does not match.
    /// </summary>
    /// <param name="state">Decrypted MFA state for SMS/Email confirmation; null for TOTP.</param>
    public async Task<string[]?> ConfirmSetupAsync(long userId, string methodId, string code, string setupToken, MfaState? state = null, CancellationToken ct = default)
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        // B7: do NOT throw on unknown methodId — that would distinguish "method exists" from
        // "token mismatch" to a probing attacker. Treat unknown methods as a generic failure,
        // identical to invalid token / userId mismatch / wrong code.
        if (!_methods.TryGetValue(methodId, out var method))
        {
            _logger.LogWarning("MFA setup confirm rejected: unknown method (userId={UserId}, method={Method})", userId, methodId);
            return null;
        }

        var payload = _setupTokenProtector.Unprotect(setupToken);
        if (payload is null)
        {
            _logger.LogWarning("MFA setup confirm rejected: invalid or expired setup token (userId={UserId})", userId);
            return null;
        }

        // Bind: token must match caller userId AND method.
        if (payload.UserId != userId || !string.Equals(payload.MethodId, methodId, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "MFA setup confirm rejected: token/caller mismatch (userId={UserId}, tokenUserId={TokenUserId}, method={Method}, tokenMethod={TokenMethod})",
                userId, payload.UserId, methodId, payload.MethodId);
            return null;
        }

        var initiation = new MfaSetupInitiation
        {
            MethodId = payload.MethodId,
            EncryptedSecret = payload.EncryptedSecret,
            Destination = payload.Destination,
            ClientResult = new MfaSetupResult { MethodId = payload.MethodId }
        };

        var swLoad = System.Diagnostics.Stopwatch.StartNew();
        var obj = await LoadOrCreateMfaPropsAsync(userId, ct).ConfigureAwait(false);
        swLoad.Stop();

        var swVerify = System.Diagnostics.Stopwatch.StartNew();
        if (!await method.ConfirmAndApplyAsync(obj.Props, initiation, code, state, ct).ConfigureAwait(false))
            return null;
        swVerify.Stop();

        var wasAlreadyEnabled = obj.Props.Enabled;

        obj.Props.Enabled = true;
        if (string.IsNullOrEmpty(obj.Props.DefaultMethod))
            obj.Props.DefaultMethod = methodId;

        string[] plainCodes;
        var swHash = System.Diagnostics.Stopwatch.StartNew();
        if (!wasAlreadyEnabled || obj.Props.RecoveryCodes is null or { Count: 0 })
        {
            var (codes, hashedCodes) = GenerateRecoveryCodes();
            obj.Props.RecoveryCodes = hashedCodes;
            plainCodes = codes;
        }
        else
        {
            // Adding a 2nd method — keep existing recovery codes; client should call regenerate to get new ones if desired.
            plainCodes = [];
        }
        swHash.Stop();

        obj.Props.FailedAttempts = 0;
        obj.Props.LockedUntil = null;

        var swSave = System.Diagnostics.Stopwatch.StartNew();
        await _redb.SaveAsync(obj).ConfigureAwait(false);
        swSave.Stop();
        swTotal.Stop();

        _logger.LogDebug(
            "MFA_CONFIRM_TIMING load={LoadMs}ms verify={VerifyMs}ms hashCodes={HashMs}ms save={SaveMs}ms total={TotalMs}ms userId={UserId} method={Method} freshCodes={FreshCodes}",
            swLoad.ElapsedMilliseconds, swVerify.ElapsedMilliseconds, swHash.ElapsedMilliseconds,
            swSave.ElapsedMilliseconds, swTotal.ElapsedMilliseconds,
            userId, methodId, plainCodes.Length);

        _logger.LogDebug("MFA setup confirmed: userId={UserId}, method={Method}", userId, methodId);
        return plainCodes;
    }

    /// <summary>
    /// Verifies an MFA code during login. Enforces lockout after too many failures.
    /// </summary>
    /// <param name="state">Decrypted MFA state for SMS/Email; null for TOTP.</param>
    public async Task<bool> VerifyAsync(long userId, string methodId, string code, MfaState? state = null, CancellationToken ct = default)
    {
        // Cross-check: caller must pass userId that matches the encrypted state.
        // Defence-in-depth against caller bugs that mix up identities between login and verify.
        if (state is not null && state.UserId != userId)
        {
            _securityLogger.LogWarning("MFA verify rejected (state.UserId != userId): caller={UserId}, state={StateUserId}", userId, state.UserId);
            return false;
        }

        var method = GetMethod(methodId);
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj is null)
            return false;

        var props = obj.Props;

        // Check lockout (with clock skew tolerance — B9 / BUG-5).
        if (IsLockedOut(props))
        {
            _securityLogger.LogWarning("MFA verify rejected (locked out): userId={UserId}", userId);
            return false;
        }

        if (await method.VerifyAsync(props, code, state, ct).ConfigureAwait(false))
        {
            props.FailedAttempts = 0;
            props.LockedUntil = null;
            props.LastVerifiedAt = _timeProvider.GetUtcNow();
            await _redb.SaveAsync(obj).ConfigureAwait(false);
            return true;
        }

        // Failed attempt
        props.FailedAttempts++;
        if (props.FailedAttempts >= _maxFailedAttempts)
        {
            props.LockedUntil = _timeProvider.GetUtcNow() + _lockoutDuration;
            _securityLogger.LogWarning("MFA lockout activated: userId={UserId}, attempts={Attempts}", userId, props.FailedAttempts);
        }

        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return false;
    }

    /// <summary>
    /// Verifies a one-time recovery code. The code is consumed (removed) on success.
    /// Failed attempts increment <see cref="MfaProps.FailedAttempts"/> and trigger lockout,
    /// matching the protection given to TOTP/SMS/Email.
    /// </summary>
    public async Task<bool> VerifyRecoveryCodeAsync(long userId, string code, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj is null)
            return false;

        var props = obj.Props;

        // Honour lockout — recovery codes are not a bypass for brute-force protection.
        if (IsLockedOut(props))
        {
            _securityLogger.LogWarning("MFA recovery rejected (locked out): userId={UserId}", userId);
            return false;
        }

        if (props.RecoveryCodes is { Count: > 0 })
        {
            // Constant-time scan over all unconsumed codes.
            // Iterate the full list even after a match to avoid leaking match-position via timing.
            var matchIndex = -1;
            bool needsRehash = false;
            for (int i = 0; i < props.RecoveryCodes.Count; i++)
            {
                var stored = props.RecoveryCodes[i];
                bool isMatch = VerifyRecoveryCodeHash(stored, code, out var legacy);
                if (isMatch && matchIndex < 0)
                {
                    matchIndex = i;
                    needsRehash = legacy;
                }
            }
            if (matchIndex >= 0)
            {
                props.RecoveryCodes.RemoveAt(matchIndex);
                if (needsRehash)
                {
                    _logger.LogDebug(
                        "MFA recovery code consumed in legacy SHA-256 format (no rehash on used code): userId={UserId}",
                        userId);
                }
                props.FailedAttempts = 0;
                props.LockedUntil = null;
                props.LastVerifiedAt = _timeProvider.GetUtcNow();

                await _redb.SaveAsync(obj).ConfigureAwait(false);
                _logger.LogDebug("MFA recovery code used: userId={UserId}, remaining={Remaining}", userId, props.RecoveryCodes.Count);
                return true;
            }
        }

        // Wrong code — count it the same way as a failed TOTP attempt.
        props.FailedAttempts++;
        if (props.FailedAttempts >= _maxFailedAttempts)
        {
            props.LockedUntil = _timeProvider.GetUtcNow() + _lockoutDuration;
            _securityLogger.LogWarning("MFA lockout activated via recovery: userId={UserId}, attempts={Attempts}", userId, props.FailedAttempts);
        }

        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return false;
    }

    /// <summary>Disables a specific MFA method for the user.</summary>
    public async Task DisableAsync(long userId, string methodId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj is null)
            return;

        switch (methodId.ToLowerInvariant())
        {
            case "totp":
                obj.Props.TotpSecret = null;
                obj.Props.TotpConfirmed = false;
                break;
            case "sms":
                obj.Props.SmsPhone = null;
                obj.Props.SmsConfirmed = false;
                break;
            case "email":
                obj.Props.OtpEmail = null;
                obj.Props.EmailConfirmed = false;
                break;
        }

        // If no methods remain confirmed — disable MFA entirely.
        var anyConfirmed = obj.Props.TotpConfirmed || obj.Props.SmsConfirmed || obj.Props.EmailConfirmed;
        if (!anyConfirmed)
        {
            obj.Props.Enabled = false;
            obj.Props.DefaultMethod = null;
            // B9 / BUG-8: archive the recovery hashes instead of nulling them out, so an
            // admin can audit «which codes were active when MFA was disabled?». The archived
            // hashes are NEVER consulted by VerifyRecoveryCodeAsync (see ArchivedRecoveryCodes
            // doc) so this does not weaken the revocation guarantee.
            ArchiveRecoveryCodes(obj.Props, reason: "disable");
            obj.Props.RecoveryCodes = null;
        }
        else if (string.Equals(obj.Props.DefaultMethod, methodId, StringComparison.OrdinalIgnoreCase))
        {
            // Pick a new default — prefer TOTP > SMS > Email
            obj.Props.DefaultMethod = obj.Props.TotpConfirmed ? "totp"
                : obj.Props.SmsConfirmed ? "sms"
                : "email";
        }

        obj.Props.FailedAttempts = 0;
        obj.Props.LockedUntil = null;

        await _redb.SaveAsync(obj).ConfigureAwait(false);
        _logger.LogDebug("MFA disabled: userId={UserId}, method={Method}", userId, methodId);
    }

    /// <summary>Returns MFA status for the user: enabled, methods, recovery codes remaining.</summary>
    public async Task<MfaStatusResult> GetStatusAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { } props)
            return new MfaStatusResult { Enabled = false, Methods = [], RecoveryCodesRemaining = 0 };

        var methods = new List<string>();
        if (props.TotpConfirmed) methods.Add("totp");
        if (props.SmsConfirmed && !string.IsNullOrEmpty(props.SmsPhone)) methods.Add("sms");
        if (props.EmailConfirmed && !string.IsNullOrEmpty(props.OtpEmail)) methods.Add("email");

        return new MfaStatusResult
        {
            Enabled = props.Enabled,
            Methods = methods.ToArray(),
            RecoveryCodesRemaining = props.RecoveryCodes?.Count ?? 0
        };
    }

    /// <summary>Regenerates recovery codes. Old codes are invalidated.</summary>
    public async Task<string[]?> RegenerateRecoveryCodesAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { Enabled: true })
            return null;

        var (plainCodes, hashedCodes) = GenerateRecoveryCodes();
        // B9 / BUG-8: archive the previous batch before overwriting.
        ArchiveRecoveryCodes(obj.Props, reason: "regenerate");
        obj.Props.RecoveryCodes = hashedCodes;
        await _redb.SaveAsync(obj).ConfigureAwait(false);

        _logger.LogDebug("MFA recovery codes regenerated: userId={UserId}", userId);
        return plainCodes;
    }

    /// <summary>Encrypts MFA state for the challenge flow (password verified → awaiting MFA code).</summary>
    public string ProtectState(MfaState state) => _stateProtector.Protect(state);

    /// <summary>Decrypts and validates MFA state. Returns null if invalid/expired.</summary>
    public MfaState? UnprotectState(string protectedState) => _stateProtector.Unprotect(protectedState);

    /// <summary>
    /// Generates a fresh OTP code for SMS/Email, dispatches it via the matching delivery channel,
    /// updates rate-limit counters, and returns a new encrypted MFA state with the code embedded.
    /// </summary>
    public async Task<MfaChallengeResult> CreateChallengeAsync(
        long userId, string username, string methodId, string? returnUrl, CancellationToken ct = default)
        => await CreateChallengeAsync(userId, username, methodId, returnUrl, knownMethods: null, ct).ConfigureAwait(false);

    /// <summary>
    /// Overload that lets callers reuse the methods array from the original MFA state, avoiding
    /// an extra DB roundtrip when the list has not changed.
    /// </summary>
    public async Task<MfaChallengeResult> CreateChallengeAsync(
        long userId, string username, string methodId, string? returnUrl,
        string[]? knownMethods, CancellationToken ct = default)
    {
        if (methodId != "sms" && methodId != "email")
            return MfaChallengeResult.Failed("method_not_challengeable");

        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj?.Props is not { Enabled: true } props)
            return MfaChallengeResult.Failed("mfa_not_enabled");

        // Determine destination
        string? destination = methodId == "sms" ? props.SmsPhone : props.OtpEmail;
        var confirmed = methodId == "sms" ? props.SmsConfirmed : props.EmailConfirmed;
        if (string.IsNullOrEmpty(destination) || !confirmed)
            return MfaChallengeResult.Failed("method_not_configured");

        // Channel must be registered (host app must wire up SMS/Email senders)
        if (!_channels.TryGetValue(methodId, out var channel))
            return MfaChallengeResult.Failed("no_channel");

        // Rate limit check
        var rateLimit = CheckOtpRateLimit(props);
        if (rateLimit > 0)
        {
            _securityLogger.LogWarning("MFA challenge rate-limited: userId={UserId}, retryAfter={RetryAfter}s", userId, rateLimit);
            return MfaChallengeResult.Failed("rate_limited", rateLimit);
        }

        // Reserve the rate-limit slot BEFORE attempting delivery — otherwise an attacker could
        // spam SMS/email indefinitely as long as the upstream provider keeps returning errors.
        // The slot is consumed on delivery attempt, success or failure alike.
        UpdateOtpRateLimitCounters(props);
        await _redb.SaveAsync(obj).ConfigureAwait(false);

        var masked = methodId == "sms" ? SmsMfaMethod.MaskPhone(destination) : EmailMfaMethod.MaskEmail(destination);

        // B3: server-side OTP store. The plaintext code lives only between issue & delivery;
        // the state blob carries just a `jti` reference, so the code never appears in URLs,
        // Referer headers, HTTP access logs or the encrypted state cookie content.
        Guid jti;
        string code;
        DateTimeOffset expiresAt;
        if (_otpStore is not null)
        {
            var ttl = TimeSpan.FromMinutes(5);
            var issued = await _otpStore.IssueAsync(userId, methodId, masked, ttl, ct).ConfigureAwait(false);
            jti = issued.Jti;
            code = issued.PlaintextCode;
            expiresAt = issued.ExpiresAt;
        }
        else
        {
            // Fallback for legacy tests that don't register IServerSideOtpStore — still OK because
            // the per-method verify path checks state.OtpMethod+state.OtpJti first; legacy path
            // uses Jti as a dummy handle and VerifyAndConsume is bypassed.
            jti = Guid.NewGuid();
            code = GenerateOtpCode();
            expiresAt = _timeProvider.GetUtcNow() + TimeSpan.FromMinutes(5);
        }

        try
        {
            await channel.SendCodeAsync(destination, code, ct).ConfigureAwait(false);
        }
        catch (MfaDeliveryException ex)
        {
            _logger.LogError(ex, "MFA delivery failed: userId={UserId}, channel={Channel}", userId, methodId);
            return MfaChallengeResult.Failed("delivery_failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MFA delivery exception: userId={UserId}, channel={Channel}", userId, methodId);
            return MfaChallengeResult.Failed("delivery_failed");
        }

        // Reuse knownMethods if provided (saves a DB roundtrip when called from MfaChallengeProcessor
        // where the original state already carries the method list).
        var methods = knownMethods ?? CollectEnabledMethods(props);

        var newState = new MfaState
        {
            Jti = Guid.NewGuid(),
            UserId = userId,
            Username = username,
            Methods = methods,
            ReturnUrl = returnUrl,
            OtpJti = jti,
            OtpDestination = masked,
            OtpMethod = methodId,
            OtpExpiresAt = expiresAt,
        };

        var protectedState = _stateProtector.Protect(newState);
        _logger.LogDebug("MFA challenge sent: userId={UserId}, method={Method}", userId, methodId);
        return MfaChallengeResult.Ok(methodId, protectedState, masked);
    }

    /// <summary>Returns the registered <see cref="IMfaMethod"/> by id (public for processors).</summary>
    public IMfaMethod GetRegisteredMethod(string methodId) => GetMethod(methodId);

    /// <summary>Loads MFA props for a user (public so processors can read state for verify).</summary>
    public async Task<MfaProps?> LoadPropsAsync(long userId, CancellationToken ct = default)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        return obj?.Props;
    }

    // --- Private helpers ---

    private IMfaMethod GetMethod(string methodId)
    {
        if (_methods.TryGetValue(methodId, out var method))
            return method;
        throw new ArgumentException($"Unknown MFA method: {methodId}", nameof(methodId));
    }

    private async Task<RedbObject<MfaProps>?> LoadMfaPropsAsync(long userId, CancellationToken _)
    {
        return await _redb.Query<MfaProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Returns the redb-object id of the MFA props row for <paramref name="userId"/>, or 0 if none.
    /// Used by callers (e.g. <see cref="Routes.Processors.MfaVerifyProcessor"/>) to acquire a row-level
    /// <c>SELECT ... FOR UPDATE</c> lock via <see cref="IRedbService.LockForUpdateAsync"/> before invoking
    /// <see cref="VerifyAsync"/> — serializes concurrent verify attempts and prevents lost-update on
    /// <see cref="MfaProps.FailedAttempts"/> / <see cref="MfaProps.LockedUntil"/>.
    /// </summary>
    internal async Task<long> GetMfaObjectIdAsync(long userId, CancellationToken _)
    {
        return await _redb.Query<MfaProps>()
            .WhereRedb(o => o.Key == userId)
            .Select(o => o.id)
            .FirstOrDefaultAsync().ConfigureAwait(false);
    }

    private async Task<RedbObject<MfaProps>> LoadOrCreateMfaPropsAsync(long userId, CancellationToken ct)
    {
        var obj = await LoadMfaPropsAsync(userId, ct).ConfigureAwait(false);
        if (obj is not null)
            return obj;

        obj = new RedbObject<MfaProps>(new MfaProps());
        obj.key = userId;
        return obj;
    }

    private (string[] plain, List<string> hashed) GenerateRecoveryCodes()
    {
        // Alphabet without ambiguous chars (0/O, 1/I/l)
        const string alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        var plain = new string[_recoveryCodeCount];
        var hashed = new string[_recoveryCodeCount];

        // Generate plaintext codes serially — UnbiasedRandom uses RandomNumberGenerator.Fill
        // on a stackalloc'd byte, which is cheap; the dominant cost is PBKDF2 below.
        for (int i = 0; i < _recoveryCodeCount; i++)
            plain[i] = GenerateSingleCode(alphabet);

        // PBKDF2 is CPU-bound per code (~80–100ms each at production iteration counts).
        // 10 codes × 90ms ≈ 900ms serially. Parallel.For distributes across cores; each
        // HashCode invocation is independent (its own salt + buffers), so no synchronisation
        // is required. Plain[] / hashed[] are written to disjoint indices.
        Parallel.For(0, _recoveryCodeCount, i =>
        {
            hashed[i] = HashCode(plain[i]);
        });

        return (plain, hashed.ToList());
    }

    /// <summary>
    /// B9 / BUG-5 helper. Returns whether the user is currently inside the lockout window,
    /// applying <see cref="RedbIdentityOptions.MfaLockoutClockSkew"/> to bias the comparison
    /// toward «still locked» when clocks may be slightly out of sync.
    /// </summary>
    private bool IsLockedOut(MfaProps props)
    {
        if (!props.LockedUntil.HasValue) return false;
        var now = _timeProvider.GetUtcNow();
        return now < props.LockedUntil.Value + _options.MfaLockoutClockSkew;
    }

    /// <summary>
    /// B9 / BUG-8 helper. Moves the current <see cref="MfaProps.RecoveryCodes"/> into
    /// <see cref="MfaProps.ArchivedRecoveryCodes"/> with a timestamp + reason. Caller is
    /// responsible for clearing <c>RecoveryCodes</c> afterwards.
    /// </summary>
    private void ArchiveRecoveryCodes(MfaProps props, string reason)
    {
        if (props.RecoveryCodes is not { Count: > 0 } codes) return;
        props.ArchivedRecoveryCodes ??= new List<MfaArchivedRecoveryCodeBatch>();
        props.ArchivedRecoveryCodes.Add(new MfaArchivedRecoveryCodeBatch
        {
            ArchivedAt = _timeProvider.GetUtcNow(),
            Reason = reason,
            HashedCodes = new List<string>(codes)
        });
    }

    private static string GenerateSingleCode(string alphabet)
    {
        // Format: XXXX-XXXX (8 chars + dash)
        // Use rejection sampling to avoid modulo bias (alphabet.Length=31, 256%31≠0)
        var sb = new StringBuilder(9);
        for (int i = 0; i < 8; i++)
        {
            if (i == 4) sb.Append('-');
            sb.Append(alphabet[UnbiasedRandom(alphabet.Length)]);
        }
        return sb.ToString();
    }

    private static int UnbiasedRandom(int range)
    {
        // Rejection sampling: discard values >= largest multiple of range that fits in a byte
        int limit = 256 - (256 % range);
        Span<byte> buf = stackalloc byte[1];
        int value;
        do
        {
            RandomNumberGenerator.Fill(buf);
            value = buf[0];
        } while (value >= limit);
        return value % range;
    }

    private string HashCode(string code)
    {
        // PBKDF2-HMAC-SHA256(password = normalized_code || pepper, salt = per-code random 16B,
        // iterations = configured work-factor, length = 32B). Format string embeds iteration count
        // so future work-factor increases verify side-by-side.
        var normalized = NormalizeRecoveryCode(code);
        var salt = RandomNumberGenerator.GetBytes(16);
        var iterations = _options.RecoveryCodePbkdf2Iterations;
        var hash = Pbkdf2Hash(normalized, salt, iterations);
        return string.Concat(
            "pbkdf2$",
            iterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "$",
            Convert.ToBase64String(salt),
            "$",
            Convert.ToBase64String(hash));
    }

    /// <summary>
    /// Returns true if <paramref name="presentedCode"/> matches the stored hash.
    /// Sets <paramref name="legacyFormat"/> = true when the stored hash is the pre-B4 SHA-256 hex
    /// representation (so the caller can log a migration event). Always uses constant-time
    /// comparison on the byte representation.
    /// </summary>
    private bool VerifyRecoveryCodeHash(string stored, string presentedCode, out bool legacyFormat)
    {
        legacyFormat = false;
        var normalized = NormalizeRecoveryCode(presentedCode);

        if (stored.StartsWith("pbkdf2$", StringComparison.Ordinal))
        {
            var parts = stored.Split('$');
            if (parts.Length != 4) return false;
            if (!int.TryParse(parts[1], System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var iterations) || iterations <= 0)
                return false;
            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException) { return false; }
            var actual = Pbkdf2Hash(normalized, salt, iterations, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }

        // Legacy format: hex-encoded SHA-256 of the normalized code (no salt, no pepper).
        legacyFormat = true;
        var legacyExpected = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        // Compare to the stored hex string after decoding back to bytes (constant-time on bytes).
        if (stored.Length != legacyExpected.Length * 2) return false;
        byte[] storedBytes;
        try
        {
            storedBytes = Convert.FromHexString(stored);
        }
        catch (FormatException) { return false; }
        return CryptographicOperations.FixedTimeEquals(storedBytes, legacyExpected);
    }

    private byte[] Pbkdf2Hash(string normalizedCode, byte[] salt, int iterations, int outputLength = 32)
    {
        var pepper = _pepperProvider.Pepper;
        var codeBytes = Encoding.UTF8.GetBytes(normalizedCode);
        var pwd = new byte[codeBytes.Length + pepper.Length];
        Buffer.BlockCopy(codeBytes, 0, pwd, 0, codeBytes.Length);
        Buffer.BlockCopy(pepper, 0, pwd, codeBytes.Length, pepper.Length);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(pwd, salt, iterations, HashAlgorithmName.SHA256, outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
        }
    }

    private static string NormalizeRecoveryCode(string code) =>
        code.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();

    /// <summary>
    /// Returns the number of seconds until the next OTP can be sent, or 0 if allowed now.
    /// Combines per-send cooldown and a sliding-window per-hour quota (B6).
    /// </summary>
    private int CheckOtpRateLimit(MfaProps props)
    {
        var now = _timeProvider.GetUtcNow();

        // Cooldown
        if (props.LastOtpSentAt is { } last)
        {
            var elapsed = now - last;
            if (elapsed < _options.OtpCooldown)
            {
                var remaining = (int)Math.Ceiling((_options.OtpCooldown - elapsed).TotalSeconds);
                return Math.Max(remaining, 1);
            }
        }

        // Sliding-window hourly quota
        var timestamps = props.RecentOtpTimestamps;
        if (timestamps is null || timestamps.Count == 0)
            return 0;

        var cutoff = now.ToUnixTimeSeconds() - (long)OtpRateLimitWindow.TotalSeconds;
        // Count entries still within the window (do not mutate here — mutation happens in
        // UpdateOtpRateLimitCounters under the same row lock).
        var insideWindow = 0;
        var oldestInside = long.MaxValue;
        foreach (var ts in timestamps)
        {
            if (ts > cutoff)
            {
                insideWindow++;
                if (ts < oldestInside) oldestInside = ts;
            }
        }

        if (insideWindow < _options.OtpMaxPerHour)
            return 0;

        // Quota reached — caller must wait until the oldest in-window entry leaves the window.
        var nextSlotUnix = oldestInside + (long)OtpRateLimitWindow.TotalSeconds;
        var waitSeconds = (int)(nextSlotUnix - now.ToUnixTimeSeconds());
        return Math.Max(waitSeconds, 1);
    }

    private void UpdateOtpRateLimitCounters(MfaProps props)
    {
        var now = _timeProvider.GetUtcNow();
        var nowUnix = now.ToUnixTimeSeconds();
        var cutoff = nowUnix - (long)OtpRateLimitWindow.TotalSeconds;

        // Prune expired timestamps in-place; allocate a fresh list if none yet.
        var timestamps = props.RecentOtpTimestamps;
        if (timestamps is null)
        {
            timestamps = new List<long>(4);
            props.RecentOtpTimestamps = timestamps;
        }
        else
        {
            timestamps.RemoveAll(ts => ts <= cutoff);
        }

        timestamps.Add(nowUnix);

        // Cap list size to bound storage. Drop oldest entries first.
        if (timestamps.Count > RecentOtpTimestampsCap)
        {
            timestamps.RemoveRange(0, timestamps.Count - RecentOtpTimestampsCap);
        }

        props.LastOtpSentAt = now;
    }

    /// <summary>Generates a 6-digit OTP code using cryptographic RNG.</summary>
    internal static string GenerateOtpCode()
    {
        Span<byte> buf = stackalloc byte[4];
        RandomNumberGenerator.Fill(buf);
        var n = BitConverter.ToUInt32(buf) % 1_000_000u;
        return n.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
