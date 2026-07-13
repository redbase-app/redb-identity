namespace redb.Identity.Web.Configuration;

/// <summary>Strong-typed OIDC + API config bound from <c>Identity</c> section.</summary>
public sealed class IdentityWebOptions
{
    /// <summary>OIDC issuer expected in id_token (must match discovery doc <c>issuer</c>).</summary>
    public string Authority { get; set; } = "";
    /// <summary>Optional override for discovery URL when issuer URL is not directly reachable
    /// (typical for reverse-proxy setups where worker listens on http://127.0.0.1:PORT but
    /// issuer is https://public-host/).</summary>
    public string? MetadataAddress { get; set; }
    /// <summary>Disable HTTPS metadata requirement (dev only — when discovery URL is plain http).</summary>
    public bool RequireHttpsMetadata { get; set; } = true;
    /// <summary>DEV ONLY. Accept ANY server certificate on the BFF's backchannel HTTP calls to the
    /// Identity host (metadata, token, revoked-sids). Use only with the bundled self-signed dev cert
    /// on localhost — never in production, where the host must present a chain-trusted certificate.</summary>
    public bool AcceptAnyBackchannelCert { get; set; }
    /// <summary>Base URL for management API calls.</summary>
    public string ApiBaseUrl { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string[] Scopes { get; set; } = ["openid", "profile", "email", "roles", "offline_access"];

    /// <summary>
    /// W6-0 — dedicated <c>client_credentials</c> service account used to publish
    /// and poll the backchannel revoked-sids list. Must be created out-of-band on
    /// the Identity host (e.g. via <c>SeedBackchannelClientOptions</c>).
    /// </summary>
    public BackchannelClientOptions BackchannelClient { get; set; } = new();

    /// <summary>W6-0 — polling client config for the revoked-sids cache.</summary>
    public RevokedSidsClientOptions RevokedSids { get; set; } = new();
}

/// <summary>W6-0 — service-account creds used by <c>RevokedSidsPollHostedService</c>.</summary>
public sealed class BackchannelClientOptions
{
    /// <summary>Client identifier of the service account.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Client secret of the service account.</summary>
    public string ClientSecret { get; set; } = "";

    /// <summary>Scopes requested via client_credentials. Default <c>identity:manage</c>.</summary>
    public string[] Scopes { get; set; } = ["identity:manage"];
}

/// <summary>W6-0 — poll-interval config for the revoked-sids cache.</summary>
public sealed class RevokedSidsClientOptions
{
    /// <summary>How often to refresh the cache from <c>/revoked-sids/since</c>. Default 60s.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(60);
}

/// <summary>Bootstrap-admin seeder config bound from <c>Bootstrap</c> section.</summary>
public sealed class BootstrapOptions
{
    /// <summary>If false, seeder is a no-op.</summary>
    public bool Enabled { get; set; }
    /// <summary>Absolute URL of the management <c>/internal/bootstrap-admin</c> endpoint.</summary>
    public string Endpoint { get; set; } = "";
    /// <summary>Pre-shared secret (constant-time compared on server). MUST come from env/secrets, never appsettings in repo.</summary>
    public string Secret { get; set; } = "";
}
