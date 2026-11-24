using System.Text;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Shared logic for extracting client credentials from <c>Authorization: Basic</c> header.
/// Per RFC 6749 §2.3.1. Used by Token, Introspection, and Revocation endpoints.
/// </summary>
internal static class BasicAuthHelper
{
    internal static void Apply(BaseValidatingContext context, OpenIddictRequest? request)
    {
        if (request is null)
            return;

        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return;

        if (!exchange.In.Headers.TryGetValue("Authorization", out var headerValue)
            || headerValue is not string auth
            || !auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var encoded = auth["Basic ".Length..].Trim();

        // The client attempted authentication through the header, so a value that cannot be read (not base64, or
        // no client_id:client_secret pair) is a failed client authentication, answered with invalid_client
        // (RFC 6749 section 5.2), not a missing client_id.
        string? decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        }
        catch (FormatException)
        {
            decoded = null;
        }

        var colonIdx = decoded?.IndexOf(':') ?? -1;
        if (decoded is null || colonIdx <= 0)
        {
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidClient,
                description: "The Authorization header does not carry readable Basic client credentials.");
            return;
        }

        request.ClientId = Uri.UnescapeDataString(decoded[..colonIdx]);
        request.ClientSecret = Uri.UnescapeDataString(decoded[(colonIdx + 1)..]);
    }
}

/// <summary>
/// Extracts client credentials from <c>Authorization: Basic</c> on the Token endpoint.
/// </summary>
internal sealed class ExtractClientCredentialsHandler
    : IOpenIddictServerHandler<ExtractTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractTokenRequestContext>()
            .UseSingletonHandler<ExtractClientCredentialsHandler>()
            .SetOrder(int.MinValue + 50_001)
            .Build();

    public ValueTask HandleAsync(ExtractTokenRequestContext context)
    {
        BasicAuthHelper.Apply(context, context.Request);
        return default;
    }
}

/// <summary>
/// Extracts client credentials from <c>Authorization: Basic</c> on the Introspection endpoint.
/// Per RFC 7662 §2.1.
/// </summary>
internal sealed class ExtractIntrospectionClientCredentialsHandler
    : IOpenIddictServerHandler<ExtractIntrospectionRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractIntrospectionRequestContext>()
            .UseSingletonHandler<ExtractIntrospectionClientCredentialsHandler>()
            .SetOrder(int.MinValue + 50_001)
            .Build();

    public ValueTask HandleAsync(ExtractIntrospectionRequestContext context)
    {
        BasicAuthHelper.Apply(context, context.Request);
        return default;
    }
}

/// <summary>
/// Extracts client credentials from <c>Authorization: Basic</c> on the Revocation endpoint.
/// Per RFC 7009 §2.1.
/// </summary>
internal sealed class ExtractRevocationClientCredentialsHandler
    : IOpenIddictServerHandler<ExtractRevocationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractRevocationRequestContext>()
            .UseSingletonHandler<ExtractRevocationClientCredentialsHandler>()
            .SetOrder(int.MinValue + 50_001)
            .Build();

    public ValueTask HandleAsync(ExtractRevocationRequestContext context)
    {
        BasicAuthHelper.Apply(context, context.Request);
        return default;
    }
}
