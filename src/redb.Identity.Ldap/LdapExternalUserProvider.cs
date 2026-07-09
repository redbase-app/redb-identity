using Microsoft.Extensions.Logging;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Ldap;
using static redb.Route.Ldap.LdapDsl;

namespace redb.Identity.Ldap;

/// <summary>
/// LDAP external user provider. Implements search+bind authentication:
/// 1. Search with service account to find user DN by uid/sAMAccountName
/// 2. Bind with found user DN + provided password to verify credentials
/// 3. Check UAC flags (if enabled) for disabled/locked accounts
/// 4. Map LDAP attributes → ExternalAuthResult
/// </summary>
public sealed class LdapExternalUserProvider : IExternalUserProvider, IAsyncDisposable
{
    private readonly LdapProviderOptions _options;
    private readonly LdapAttributeMapper _mapper;
    private readonly ILogger<LdapExternalUserProvider> _logger;

    // Persistent search endpoint (connection pool)
    private readonly LdapComponent _searchComponent;
    private readonly IEndpoint _searchEndpoint;
    private readonly IProducer _searchProducer;
    private bool _started;

    public string ProviderName => _options.ProviderName;
    public int Priority => _options.Priority;
    internal LdapProviderOptions Options => _options;

    public LdapExternalUserProvider(
        LdapProviderOptions options,
        ILogger<LdapExternalUserProvider> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options.Validate();
        _mapper = new LdapAttributeMapper(options);

        // Build persistent search endpoint with connection pool and dynamic filter
        var requestedAttrs = _options.CheckAccountStatus
            ? _mapper.GetRequestedAttributes().Append("userAccountControl").Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            : _mapper.GetRequestedAttributes();

        var searchBuilder = Search(_options.UserBaseDn)
            .Server(_options.Server)
            .Port(_options.EffectivePort)
            .Filter("${header.ldapSearchFilter}")  // resolved per-request from exchange header
            .Scope(MapScope(_options.SearchScope))
            .Attributes(requestedAttrs)
            .SizeLimit(2);

        ApplyConnectionSettings(searchBuilder);

        _searchComponent = new LdapComponent();
        _searchEndpoint = _searchComponent.CreateEndpoint(EndpointUriParser.Parse(searchBuilder.Build()));
        _searchProducer = _searchEndpoint.CreateProducer();

        _logger.LogDebug(
            "LDAP provider '{Provider}' configured: server={Server}:{Port}, baseDn={BaseDn}",
            _options.ProviderName, _options.Server, _options.EffectivePort, _options.UserBaseDn);
    }

    private async Task EnsureStartedAsync(CancellationToken ct)
    {
        if (_started) return;
        await _searchProducer.Start(ct).ConfigureAwait(false);
        _started = true;
    }

    public async Task<ExternalAuthResult?> AuthenticateAsync(
        string username, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;

        var (bareUsername, domain) = ParseDomainHint(username);

        if (_options.Domains.Length > 0 && domain is not null)
        {
            if (!_options.Domains.Any(d => d.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                return null;
        }

        var searchUsername = domain is not null ? bareUsername : username;

        try
        {
            // Pre-flight DNS+TCP probe — fails fast on unreachable hosts instead
            // of waiting on the OS-level SYN retransmit timeout (~21 s on Windows).
            // LdapForNet's OperationTimeout only caps the post-connect exchange.
            await LdapConnectivityProbe.ProbeAsync(
                _options.Server, _options.EffectivePort,
                _options.ConnectTimeoutSeconds, ct).ConfigureAwait(false);

            var entry = await SearchUserAsync(searchUsername, ct).ConfigureAwait(false);
            if (entry == null)
            {
                _logger.LogDebug("LDAP user not found: {Username}", searchUsername);
                return null;
            }

            var bindOk = await BindUserAsync(entry.Dn, password, ct).ConfigureAwait(false);
            if (!bindOk)
            {
                _logger.LogDebug("LDAP bind failed for DN of user: {Username}", searchUsername);
                return ExternalAuthResult.Failed("Invalid credentials");
            }

            // Check UAC flags (AD only)
            if (_options.CheckAccountStatus)
            {
                var uacResult = CheckAccountStatus(entry, searchUsername);
                if (uacResult is not null)
                    return uacResult;
            }

            var result = _mapper.MapToResult(entry);

            // Add password_expired claim if applicable
            if (_options.CheckAccountStatus)
            {
                var uacString = entry.GetString("userAccountControl");
                if (uacString is not null && int.TryParse(uacString, out var uacValue))
                {
                    var flags = (UserAccountControlFlags)uacValue;
                    if (flags.HasFlag(UserAccountControlFlags.PasswordExpired))
                    {
                        result.AdditionalClaims ??= new Dictionary<string, string>();
                        result.AdditionalClaims["password_expired"] = "true";
                    }
                }
            }

            _logger.LogInformation("LDAP authentication succeeded: {Username}", searchUsername);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "LDAP authentication error for user '{Username}' on {Server}:{Port}",
                searchUsername, _options.Server, _options.EffectivePort);
            throw;
        }
    }

    private ExternalAuthResult? CheckAccountStatus(LdapEntry entry, string username)
    {
        var uacString = entry.GetString("userAccountControl");
        if (uacString is null) return null; // attribute not present → graceful skip

        if (!int.TryParse(uacString, out var uacValue))
        {
            _logger.LogDebug("Non-numeric userAccountControl for '{Username}', skipping check", username);
            return null;
        }

        var flags = (UserAccountControlFlags)uacValue;

        if (flags.HasFlag(UserAccountControlFlags.AccountDisable))
            return ExternalAuthResult.Failed("Account is disabled");

        if (flags.HasFlag(UserAccountControlFlags.Lockout))
            return ExternalAuthResult.Failed("Account is locked out");

        return null;
    }

    private async Task<LdapEntry?> SearchUserAsync(string username, CancellationToken ct)
    {
        var filter = string.Format(_options.UserFilter, EscapeLdapFilter(username));

        // Use persistent search producer (connection pool) with per-request filter
        await EnsureStartedAsync(ct).ConfigureAwait(false);
        var exchange = new Exchange(new Message());
        exchange.In.Headers["ldapSearchFilter"] = filter;

        await _searchProducer.Process(exchange, ct).ConfigureAwait(false);

        if (exchange.In.Body is not List<LdapEntry> entries || entries.Count == 0)
            return null;

        if (entries.Count > 1)
        {
            _logger.LogWarning(
                "Ambiguous LDAP search: {Count} entries for '{Username}'",
                entries.Count, username);
            return null; // reject ambiguous results
        }

        _logger.LogDebug("LDAP search found {Count} entry for '{Username}'", entries.Count, username);
        return entries[0];
    }

    private async Task<bool> BindUserAsync(string userDn, string password, CancellationToken ct)
    {
        // Ephemeral endpoint for bind — each user gets isolated connection (security)
        var builder = Bind(_options.UserBaseDn)
            .Server(_options.Server)
            .Port(_options.EffectivePort);

        ApplyConnectionSettings(builder);

        var component = new LdapComponent();
        var endpoint = component.CreateEndpoint(EndpointUriParser.Parse(builder.Build()));
        var producer = endpoint.CreateProducer();

        try
        {
            await producer.Start(ct).ConfigureAwait(false);

            var exchange = new Exchange(new Message());
            exchange.In.Headers[LdapHeaders.AuthDn] = userDn;
            exchange.In.Headers[LdapHeaders.AuthPassword] = password;

            await producer.Process(exchange, ct).ConfigureAwait(false);

            return exchange.In.Body is true;
        }
        finally
        {
            await producer.Stop(ct).ConfigureAwait(false);
            (endpoint as IDisposable)?.Dispose();
        }
    }

    private void ApplyConnectionSettings(LdapBuilder builder)
    {
        if (!string.IsNullOrWhiteSpace(_options.BindDn))
            builder.BindDn(_options.BindDn);

        if (!string.IsNullOrWhiteSpace(_options.BindPassword))
            builder.BindPassword(_options.BindPassword);

        if (_options.UseSsl)
            builder.Ssl();

        if (_options.UseStartTls)
            builder.StartTls();

        if (_options.SkipCertificateValidation)
            builder.SkipCertificateValidation();

        if (_options.MaxConnections != 5)
            builder.MaxConnections(_options.MaxConnections);

        if (_options.OperationTimeoutSeconds > 0)
            builder.OperationTimeout(_options.OperationTimeoutSeconds * 1000);
    }

    /// <summary>
    /// Extracts bare username and domain hint from "user@domain" or "DOMAIN\user" formats.
    /// Returns the original input and null domain if no hint is detected.
    /// </summary>
    internal static (string username, string? domain) ParseDomainHint(string input)
    {
        // user@domain.com → (user, domain.com)
        var atIdx = input.IndexOf('@');
        if (atIdx > 0 && atIdx < input.Length - 1)
            return (input[..atIdx], input[(atIdx + 1)..]);

        // DOMAIN\user → (user, DOMAIN)
        var bsIdx = input.IndexOf('\\');
        if (bsIdx > 0 && bsIdx < input.Length - 1)
            return (input[(bsIdx + 1)..], input[..bsIdx]);

        return (input, null);
    }

    /// <summary>
    /// Escapes special characters in LDAP filter values (RFC 4515 §3).
    /// Prevents LDAP injection attacks.
    /// </summary>
    internal static string EscapeLdapFilter(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;

        // RFC 4515: escape *, (, ), \, NUL
        return value
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    private static LdapSearchScope MapScope(LdapSearchScopeOption scope) => scope switch
    {
        LdapSearchScopeOption.Base => LdapSearchScope.Base,
        LdapSearchScopeOption.OneLevel => LdapSearchScope.OneLevel,
        LdapSearchScopeOption.Subtree => LdapSearchScope.Subtree,
        _ => LdapSearchScope.Subtree
    };

    public async ValueTask DisposeAsync()
    {
        if (_started)
        {
            await _searchProducer.Stop(CancellationToken.None).ConfigureAwait(false);
            _started = false;
        }
        (_searchEndpoint as IDisposable)?.Dispose();
    }
}
