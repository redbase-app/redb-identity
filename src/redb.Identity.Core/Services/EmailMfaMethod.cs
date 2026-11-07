using redb.Identity.Core.Mfa;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Email OTP MFA method.
/// Stores the user's email in <see cref="MfaProps.OtpEmail"/>. The OTP code itself
/// is persisted server-side in <see cref="MfaOtpProps"/> (SHA-256 hashed, single-use
/// under <c>LockForUpdate</c>) via <see cref="IServerSideOtpStore"/> — the encrypted
/// <see cref="MfaState"/> only carries a jti reference (B3).
/// </summary>
internal sealed class EmailMfaMethod : IMfaMethod
{
    private readonly IServerSideOtpStore? _otpStore;

    public EmailMfaMethod(IServerSideOtpStore? otpStore = null)
    {
        _otpStore = otpStore;
    }

    public string MethodId => "email";

    public Task<MfaSetupInitiation> InitiateSetupAsync(string username, string? destination = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            return Task.FromResult(new MfaSetupInitiation
            {
                MethodId = MethodId,
                ClientResult = new MfaSetupResult
                {
                    MethodId = MethodId,
                    Extra = new Dictionary<string, object> { ["error"] = "Email address is required" }
                }
            });
        }

        var email = NormalizeEmail(destination);
        if (email is null)
        {
            return Task.FromResult(new MfaSetupInitiation
            {
                MethodId = MethodId,
                ClientResult = new MfaSetupResult
                {
                    MethodId = MethodId,
                    Extra = new Dictionary<string, object> { ["error"] = "Invalid email address" }
                }
            });
        }

        return Task.FromResult(new MfaSetupInitiation
        {
            MethodId = MethodId,
            Destination = email,
            ClientResult = new MfaSetupResult
            {
                MethodId = MethodId,
                Extra = new Dictionary<string, object> { ["masked_email"] = MaskEmail(email) }
            }
        });
    }

    public async Task<bool> ConfirmAndApplyAsync(MfaProps props, MfaSetupInitiation initiation, string code, MfaState? state = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(props);
        ArgumentNullException.ThrowIfNull(initiation);

        if (string.IsNullOrEmpty(initiation.Destination))
            return false;

        if (!await VerifyAgainstStateAsync(state, code, ct).ConfigureAwait(false))
            return false;

        props.OtpEmail = initiation.Destination;
        props.EmailConfirmed = true;
        return true;
    }

    public Task<bool> VerifyAsync(MfaProps props, string code, MfaState? state = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(props);
        return VerifyAgainstStateAsync(state, code, ct);
    }

    private async Task<bool> VerifyAgainstStateAsync(MfaState? state, string code, CancellationToken ct)
    {
        if (state is null) return false;
        if (state.OtpMethod != MethodId) return false;
        if (string.IsNullOrEmpty(code)) return false;

        // B3: server-side OTP store is the authoritative source; jti must be present.
        if (_otpStore is null || !state.OtpJti.HasValue) return false;

        var res = await _otpStore.VerifyAndConsumeAsync(state.OtpJti.Value, state.UserId, code, ct).ConfigureAwait(false);
        return res.Success;
    }

    internal static string? NormalizeEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;

        var trimmed = input.Trim().ToLowerInvariant();
        var atIdx = trimmed.IndexOf('@');
        if (atIdx <= 0 || atIdx == trimmed.Length - 1) return null;
        if (trimmed.Length < 5) return null;
        // Domain must contain at least one dot
        if (!trimmed[(atIdx + 1)..].Contains('.')) return null;

        return trimmed;
    }

    internal static string MaskEmail(string email)
    {
        var parts = email.Split('@');
        if (parts.Length != 2) return "****";
        var local = parts[0];
        var domain = parts[1];
        if (local.Length <= 1) return $"*@{domain}";
        return $"{local[0]}***@{domain}";
    }
}
