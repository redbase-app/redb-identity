namespace redb.Identity.Ldap;

/// <summary>
/// Shared LDAP connection settings. Base class for both
/// <see cref="LdapProviderOptions"/> and <see cref="LdapSyncOptions"/>.
/// </summary>
public class LdapConnectionSettings
{
    /// <summary>LDAP server hostname or IP. Default: "localhost".</summary>
    public string Server { get; set; } = "localhost";

    /// <summary>LDAP port. Default: 389 (636 for LDAPS).</summary>
    public int Port { get; set; } = 389;

    /// <summary>Use LDAPS (SSL/TLS on connect). Default: false.</summary>
    public bool UseSsl { get; set; }

    /// <summary>Upgrade to TLS via STARTTLS on the plain port. Default: false.</summary>
    public bool UseStartTls { get; set; }

    /// <summary>Skip server certificate validation (development only!). Default: false.</summary>
    public bool SkipCertificateValidation { get; set; }

    /// <summary>Bind DN for service-account search. Required for search+bind flow.</summary>
    public string? BindDn { get; set; }

    /// <summary>Bind password for service-account search.</summary>
    public string? BindPassword { get; set; }

    /// <summary>Client-side timeout for a single LDAP operation in seconds. 0 = no limit. Default: 10.</summary>
    public int OperationTimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Bounded DNS+TCP pre-flight probe timeout in seconds. <c>0</c> disables the
    /// probe (rely on OS-level retransmit timeouts — not recommended).
    /// <para>
    /// LdapForNet's <see cref="OperationTimeoutSeconds"/> only caps the LDAP-protocol
    /// exchange after the socket is established; it does NOT bound DNS resolution
    /// nor TCP <c>connect()</c>. On Windows the OS-level SYN retransmit takes ~21 s
    /// for a routed-but-silent destination, which would block login threads on a
    /// downed AD controller. The pre-flight probe ensures we fail fast within this
    /// window. Default: 10.
    /// </para>
    /// </summary>
    public int ConnectTimeoutSeconds { get; set; } = 10;

    /// <summary>Maximum number of pooled connections. Default: 5.</summary>
    public int MaxConnections { get; set; } = 5;

    /// <summary>
    /// Returns the effective LDAP port (636 if SSL enabled and default port unchanged).
    /// </summary>
    public int EffectivePort => UseSsl && Port == 389 ? 636 : Port;

    /// <summary>
    /// Validates the connection settings.
    /// </summary>
    public void ValidateConnection()
    {
        if (string.IsNullOrWhiteSpace(Server))
            throw new InvalidOperationException($"{GetType().Name}.Server is required.");

        if (Port is <= 0 or > 65535)
            throw new InvalidOperationException($"{GetType().Name}.Port is out of range: {Port}.");

        if (UseSsl && UseStartTls)
            throw new InvalidOperationException(
                $"{GetType().Name}: UseSsl and UseStartTls are mutually exclusive.");

        if (!string.IsNullOrWhiteSpace(BindDn) && string.IsNullOrWhiteSpace(BindPassword))
            throw new InvalidOperationException(
                $"{GetType().Name}: BindDn is set but BindPassword is empty.");

        if (string.IsNullOrWhiteSpace(BindDn) && !string.IsNullOrWhiteSpace(BindPassword))
            throw new InvalidOperationException(
                $"{GetType().Name}: BindPassword is set but BindDn is empty.");
    }
}
