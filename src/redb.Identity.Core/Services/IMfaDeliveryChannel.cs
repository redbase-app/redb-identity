namespace redb.Identity.Core.Services;

/// <summary>
/// SPI for delivering MFA codes via external channels (SMS, Email).
/// </summary>
/// <remarks>
/// Implementations are provided by external packages (e.g. redb.Identity.Sms, redb.Identity.Email)
/// or registered by the host application. Core defines only the contract.
/// </remarks>
public interface IMfaDeliveryChannel
{
    /// <summary>Channel identifier matching <see cref="IMfaMethod.MethodId"/>: "sms", "email".</summary>
    string ChannelId { get; }

    /// <summary>Human-readable display name (e.g. "SMS", "Email").</summary>
    string DisplayName { get; }

    /// <summary>
    /// Sends the OTP code to the destination.
    /// </summary>
    /// <param name="destination">Phone number (E.164) for SMS, email address for email.</param>
    /// <param name="code">6-digit OTP code.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="Exceptions.MfaDeliveryException">Thrown when delivery fails.</exception>
    Task SendCodeAsync(string destination, string code, CancellationToken ct = default);
}
