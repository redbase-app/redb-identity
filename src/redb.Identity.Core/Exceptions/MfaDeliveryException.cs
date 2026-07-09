namespace redb.Identity.Core.Exceptions;

/// <summary>
/// Thrown by <see cref="Services.IMfaDeliveryChannel"/> implementations when OTP delivery fails.
/// </summary>
public sealed class MfaDeliveryException : Exception
{
    public string ChannelId { get; }
    public string? Destination { get; }

    public MfaDeliveryException(string channelId, string? destination, string message, Exception? inner = null)
        : base(message, inner)
    {
        ChannelId = channelId;
        Destination = destination;
    }
}
