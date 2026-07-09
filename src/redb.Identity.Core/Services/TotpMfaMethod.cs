using System.Security.Cryptography;
using OtpNet;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// TOTP (RFC 6238) MFA method using Otp.NET.
/// Stateless: receives <see cref="MfaProps"/> and operates on its TOTP fields.
/// </summary>
internal sealed class TotpMfaMethod : IMfaMethod
{
    public string MethodId => "totp";

    private readonly MfaSecretProtector _secretProtector;
    private readonly string _issuerName;
    private readonly int _secretLength = 20;   // 160 bit per RFC 4226
    private readonly int _codeDigits = 6;
    private readonly int _periodSeconds = 30;
    private readonly int _skewSteps = 1;       // ±30s tolerance

    public TotpMfaMethod(MfaSecretProtector secretProtector, string issuerName = "redb.Identity")
    {
        _secretProtector = secretProtector;
        _issuerName = issuerName;
    }

    public Task<MfaSetupInitiation> InitiateSetupAsync(string username, string? destination = null, CancellationToken ct = default)
    {
        // destination is ignored for TOTP — the secret is generated server-side.
        var key = RandomNumberGenerator.GetBytes(_secretLength);
        var base32Secret = Base32Encoding.ToString(key);
        var encryptedSecret = _secretProtector.Protect(base32Secret);

        var qrUri = $"otpauth://totp/{Uri.EscapeDataString(_issuerName)}:{Uri.EscapeDataString(username)}" +
                    $"?secret={base32Secret}&issuer={Uri.EscapeDataString(_issuerName)}" +
                    $"&digits={_codeDigits}&period={_periodSeconds}";

        var clientResult = new MfaSetupResult
        {
            MethodId = MethodId,
            SecretBase32 = base32Secret,
            QrUri = qrUri
        };

        return Task.FromResult(new MfaSetupInitiation
        {
            MethodId = MethodId,
            EncryptedSecret = encryptedSecret,
            ClientResult = clientResult
        });
    }

    public Task<bool> ConfirmAndApplyAsync(MfaProps props, MfaSetupInitiation initiation, string code, MfaState? state = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(props);
        ArgumentNullException.ThrowIfNull(initiation);

        if (string.IsNullOrEmpty(initiation.EncryptedSecret))
            return Task.FromResult(false);

        // Verify the supplied code against the candidate secret WITHOUT touching props yet.
        if (!TryVerifyCodeWithSecret(initiation.EncryptedSecret, code, out var step))
            return Task.FromResult(false);

        // Atomic apply: secret + confirmation flag + replay-protection seed.
        props.TotpSecret = initiation.EncryptedSecret;
        props.TotpConfirmed = true;
        props.LastTotpStep = step;
        return Task.FromResult(true);
    }

    public Task<bool> VerifyAsync(MfaProps props, string code, MfaState? state = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(props);
        // state is ignored for TOTP.
        if (!TryVerifyCode(props, code, out var step))
            return Task.FromResult(false);

        // RFC 6238 §5.2: reject codes from a previously accepted (or earlier) time-step
        // to prevent replay within the verification window.
        // Caller (B1) must hold a row-lock + transaction so two concurrent verifies for the
        // same user serialize on the read-then-write of LastTotpStep.
        if (props.LastTotpStep.HasValue && step <= props.LastTotpStep.Value)
            return Task.FromResult(false);

        props.LastTotpStep = step;
        return Task.FromResult(true);
    }

    private bool TryVerifyCode(MfaProps props, string code, out long step)
    {
        if (string.IsNullOrEmpty(props.TotpSecret))
        {
            step = 0;
            return false;
        }
        return TryVerifyCodeWithSecret(props.TotpSecret, code, out step);
    }

    private bool TryVerifyCodeWithSecret(string encryptedSecret, string code, out long step)
    {
        step = 0;
        if (string.IsNullOrEmpty(encryptedSecret) || string.IsNullOrEmpty(code))
            return false;

        var base32Secret = _secretProtector.Unprotect(encryptedSecret);
        if (base32Secret is null)
            return false;

        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: _periodSeconds, totpSize: _codeDigits);
        var window = new VerificationWindow(previous: _skewSteps, future: _skewSteps);

        return totp.VerifyTotp(code, out step, window);
    }
}
