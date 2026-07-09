using redb.Identity.Core.Mfa;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// SMS OTP MFA method.
/// Stores the user's phone in <see cref="MfaProps.SmsPhone"/>. The OTP code itself
/// is persisted server-side in <see cref="MfaOtpProps"/> (SHA-256 hashed, single-use
/// under <c>LockForUpdate</c>) via <see cref="IServerSideOtpStore"/> — the encrypted
/// <see cref="MfaState"/> only carries a jti reference (B3).
/// </summary>
internal sealed class SmsMfaMethod : IMfaMethod
{
    private readonly IServerSideOtpStore? _otpStore;

    public SmsMfaMethod(IServerSideOtpStore? otpStore = null)
    {
        _otpStore = otpStore;
    }

    public string MethodId => "sms";

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
                    Extra = new Dictionary<string, object> { ["error"] = "Phone number is required" }
                }
            });
        }

        var phone = NormalizePhone(destination);
        if (phone is null)
        {
            return Task.FromResult(new MfaSetupInitiation
            {
                MethodId = MethodId,
                ClientResult = new MfaSetupResult
                {
                    MethodId = MethodId,
                    Extra = new Dictionary<string, object> { ["error"] = "Invalid phone number format" }
                }
            });
        }

        return Task.FromResult(new MfaSetupInitiation
        {
            MethodId = MethodId,
            Destination = phone,
            ClientResult = new MfaSetupResult
            {
                MethodId = MethodId,
                Extra = new Dictionary<string, object> { ["masked_phone"] = MaskPhone(phone) }
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

        // Atomic apply.
        props.SmsPhone = initiation.Destination;
        props.SmsConfirmed = true;
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

    internal static string? NormalizePhone(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;

        var digits = new string(input.Where(c => char.IsDigit(c) || c == '+').ToArray());
        var hasPlus = digits.StartsWith('+');
        if (hasPlus) digits = digits[1..];

        if (digits.Length < 10 || digits.Length > 15) return null;
        if (!digits.All(char.IsDigit)) return null;

        return "+" + digits;
    }

    internal static string MaskPhone(string phone)
    {
        if (string.IsNullOrEmpty(phone) || phone.Length <= 4) return "****";
        // Keep leading "+" + first digit, mask middle, keep last 4
        var prefix = phone.StartsWith('+') ? phone[..2] : phone[..1];
        return prefix + "***" + phone[^4..];
    }
}
