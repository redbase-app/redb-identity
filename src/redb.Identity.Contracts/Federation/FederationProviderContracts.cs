using System.ComponentModel.DataAnnotations;
using redb.Identity.Contracts.Common;

namespace redb.Identity.Contracts.Federation;

/// <summary>
/// H8 (DoD §4 gap (e)): admin-API DTO for an PROPS-stored federation provider config.
/// <see cref="ClientSecret"/> is write-only — the API never returns the plaintext, only
/// <see cref="HasSecret"/>. To rotate, send a new <see cref="ClientSecret"/>; to clear,
/// send the empty string.
/// </summary>
public sealed class FederationProviderResponse
{
    public required string Id { get; init; }
    public required string ProviderId { get; init; }
    public required string Kind { get; init; }
    public required string DisplayName { get; init; }
    public string? Authority { get; init; }
    public required string ClientId { get; init; }
    /// <summary>True iff a non-empty encrypted client secret is stored at rest.</summary>
    public bool HasSecret { get; init; }
    public required IReadOnlyList<string> Scopes { get; init; }
    public bool AutoProvision { get; init; }
    public bool Enabled { get; init; }
    public int Priority { get; init; }
    public Dictionary<string, string>? ClaimMappings { get; init; }
}

public sealed class CreateFederationProviderRequest
{
    [Required, RegularExpression("^[a-z0-9][a-z0-9_-]*$",
        ErrorMessage = "ProviderId must be lowercase, start with letter/digit, and contain only [a-z0-9_-].")]
    public required string ProviderId { get; init; }

    [Required, RegularExpression("^(oidc|github)$",
        ErrorMessage = "Kind must be one of: oidc | github.")]
    public required string Kind { get; init; }

    [Required, StringLength(200, MinimumLength = 1)]
    public required string DisplayName { get; init; }

    [Url]
    public string? Authority { get; init; }

    [Required, StringLength(200, MinimumLength = 1)]
    public required string ClientId { get; init; }

    /// <summary>OAuth2 client_secret. Encrypted at rest via DataProtection. Write-only.</summary>
    public string? ClientSecret { get; init; }

    public string[]? Scopes { get; init; }
    public bool AutoProvision { get; init; } = true;
    public bool Enabled { get; init; } = true;
    public int Priority { get; init; } = 100;
    public Dictionary<string, string>? ClaimMappings { get; init; }
}

public sealed class UpdateFederationProviderRequest
{
    [Required] public string Id { get; set; } = string.Empty;
    public string? Kind { get; init; }
    public string? DisplayName { get; init; }
    public string? Authority { get; init; }
    public string? ClientId { get; init; }
    /// <summary>Send a new value to rotate, or empty string to clear. Null = leave unchanged.</summary>
    public string? ClientSecret { get; init; }
    public string[]? Scopes { get; init; }
    public bool? AutoProvision { get; init; }
    public bool? Enabled { get; init; }
    public int? Priority { get; init; }
    public Dictionary<string, string>? ClaimMappings { get; init; }
}

/// <summary>
/// Public projection of a federation provider safe for unauthenticated callers (login
/// pages, third-party UIs). Carries only the fields needed to render a sign-in button —
/// never <c>ClientSecret</c>, <c>Authority</c>, <c>ClaimMappings</c>, or any other
/// secret/configuration detail.
/// </summary>
/// <param name="ProviderId">Stable identifier echoed back to <c>/connect/external-login?provider=</c>.</param>
/// <param name="DisplayName">Human-readable label, e.g. "Google".</param>
/// <param name="Kind">Provider kind: <c>oidc</c> or <c>github</c>. Allows callers to pick brand-specific icons.</param>
/// <param name="Priority">Display order. Lower = shown first.</param>
public sealed record PublicFederationProviderDescriptor(
    string ProviderId,
    string DisplayName,
    string Kind,
    int Priority);
