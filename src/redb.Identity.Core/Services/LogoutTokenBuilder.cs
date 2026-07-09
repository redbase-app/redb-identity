using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace redb.Identity.Core.Services;

/// <summary>
/// Builds OIDC Back-Channel Logout 1.0 <c>logout_token</c> JWTs (RFC: OIDC Back-Channel
/// Logout 1.0 §2.4). Uses the same signing keys as the issuer's id_token, so any RP that
/// already validates id_tokens from this issuer can validate the logout_token unchanged.
/// </summary>
public sealed class LogoutTokenBuilder
{
    /// <summary>Mandatory event identifier per OIDC Back-Channel Logout 1.0 §2.4.</summary>
    public const string LogoutEventIdentifier = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly JwtSecurityTokenHandler _tokenHandler = new() { MapInboundClaims = false };

    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<LogoutTokenBuilder>? _logger;

    public LogoutTokenBuilder(
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        TimeProvider? timeProvider = null,
        ILogger<LogoutTokenBuilder>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(serverOptions);
        _serverOptions = serverOptions;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    /// <summary>
    /// Returns <c>true</c> when at least one signing credential is configured. Without one
    /// we cannot produce a logout_token and backchannel logout must be a no-op.
    /// </summary>
    public bool CanIssue => _serverOptions.CurrentValue.SigningCredentials.Count > 0;

    /// <summary>
    /// Builds a signed logout_token for a given RP.
    /// </summary>
    /// <param name="audience">RP's client_id (becomes the <c>aud</c> claim).</param>
    /// <param name="subject">End-user identifier (becomes the <c>sub</c> claim).</param>
    /// <param name="sessionId">
    /// Optional session id. When not null/empty, an <c>sid</c> claim is added so the RP can
    /// terminate only the matching session instead of all sessions for the user.
    /// </param>
    /// <returns>A signed JWS string, or <c>null</c> when no signing key is configured.</returns>
    public string? Build(string audience, string subject, string? sessionId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(audience);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var opts = _serverOptions.CurrentValue;
        var signing = opts.SigningCredentials.FirstOrDefault();
        if (signing is null)
        {
            _logger?.LogWarning("No signing credential configured — cannot issue logout_token for {Audience}.", audience);
            return null;
        }

        var issuer = opts.Issuer?.ToString().TrimEnd('/') ?? string.Empty;
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        // OIDC Back-Channel Logout 1.0 §2.4:
        // - MUST contain: iss, aud, iat, jti, events
        // - MUST contain at least one of: sub, sid
        // - MUST NOT contain: nonce
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            // events is a JSON object; we serialize it as a literal so JwtPayload doesn't escape it.
            new("events", $"{{\"{LogoutEventIdentifier}\":{{}}}}", JsonClaimValueTypes.Json),
        };

        if (!string.IsNullOrEmpty(sessionId))
            claims.Add(new Claim("sid", sessionId));

        var token = new JwtSecurityToken(
            issuer: string.IsNullOrEmpty(issuer) ? null : issuer,
            audience: audience,
            claims: claims,
            notBefore: null,
            expires: null, // logout_token has no exp per spec; iat + clock skew is what RP checks
            signingCredentials: signing);

        // iat is set automatically by JwtSecurityToken when not in claims; force it to our TimeProvider.
        token.Payload[JwtRegisteredClaimNames.Iat] = new DateTimeOffset(now).ToUnixTimeSeconds();

        return _tokenHandler.WriteToken(token);
    }
}
